"""Render the hash-bound ScenarioLink instruction indexes as addressable source listings."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from build_script_program import FORMAT, SOURCES
from vm_control_semantics import ARITHMETIC, COMPARISONS
from vm_handlers import ROOT

OUT = ROOT / 'analysis/decompiled-scenario'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def quoted(value):
    return json.dumps(value, ensure_ascii=False)


def destination(selector, name, labels):
    offset = labels.get(selector, {}).get(name)
    return f'b{selector:02x}::{name}@' + (f'{offset:08x}' if offset is not None else 'runtime')


def render(row, labels):
    op = row['op']
    if 'text' in row:
        return 'text ' + quoted(row['text']['text']) + '  #' + row['text']['id']
    if 'ruby' in row:
        return 'ruby ' + ', '.join(quoted(entry['text'])+' #'+entry['id'] for entry in row['ruby'])
    if 'resource' in row:
        return 'resource_' + f'{op:02x} ' + quoted(row['resource'])
    args = row.get('operands', {})
    if args.get('kind') in ('label_transfer','label_transfer_variant','label_marker'):
        return args['kind']+' '+destination(args['block_selector'],args['label'],labels)
    if args.get('kind') in ('variable_operation','conditional_transfer'):
        rhs = str(args['rhs']) if args['rhs_kind']=='signed_immediate' else f"var[{args['rhs']}]"
        if args['kind']=='variable_operation':
            verb = ARITHMETIC.get(args['operator'],f"operator_{args['operator']}")
            return f"var[{args['variable_id']}] {verb} {rhs}"
        verb = COMPARISONS.get(args['operator'],f"operator_{args['operator']}")
        target = destination(args['block_selector'],args['label'],labels)
        return f"{args['jump_when']} (var[{args['variable_id']}] {verb} {rhs}) -> {target}"
    if args.get('kind')=='choice_setup':
        options = [f"{opt['index']}:{destination(opt['block_selector'],opt['label'],labels)} flag={opt['raw_flag']}"
                   for opt in args['options']]
        return f"choice mode={args['mode']} ["+', '.join(options)+'] extra='+args['extra_hex']
    if op==0x7f:  # 12E180 -> 119A18 reads count routes, then a separate fallback.
        raw = bytes.fromhex(row['raw_hex'])
        count, cursor = raw[2], 3
        routes = []
        for _ in range(count+1):
            selector = raw[cursor]
            end = raw.index(0,cursor+1)
            routes.append(destination(selector,raw[cursor+1:end].decode('ascii'),labels))
            cursor = end+1
        if cursor!=len(raw) or count>6:
            raise ValueError(f"Unexpected actor-selection layout at {row['offset']:x}")
        return 'actor_choice ['+', '.join(routes[:-1])+'] fallback='+routes[-1]
    return 'op_' + f'{op:02x}' + ((' '+row['raw_hex'][2:]) if len(row['raw_hex'])>2 else '')


def export(name, expected_sha):
    envelope = json.loads((ROOT/'analysis/script-programs'/f'{name}.program.json').read_bytes())
    if envelope['format']!=FORMAT or digest(envelope['payload'].encode())!=envelope['sha256']:
        raise ValueError(f'Invalid {name} instruction index')
    program = json.loads(envelope['payload'])
    original = (ROOT/'local/assets/SCENARIO'/f'{name}.sn4').read_bytes()
    if digest(original)!=expected_sha or program['source']['sha256']!=expected_sha:
        raise ValueError(f'{name} source identity mismatch')
    target = OUT/name
    target.mkdir(parents=True,exist_ok=True)
    labels = {b['selector']:b['labels'] for b in program['blocks']}
    blocks = []
    for b in program['blocks']:
        names = defaultdict(list)
        for symbol,addr in b['labels'].items():
            names[addr].append(symbol)
        counts = Counter()
        addr = b['code_start']
        lines = [f"; {name}.sn4   sha256 {expected_sha}", f"; selector {b['selector']}   file offsets in hex",
                 '; Columns: original file offset | opcode | recovered operands or raw operand bytes.']
        for row in b['instructions']:
            raw = bytes.fromhex(row['raw_hex'])
            if addr!=row['offset'] or raw[0]!=row['op'] or raw!=original[addr:row['next']]:
                raise ValueError(f'{name} source byte mismatch at {addr:x}')
            for symbol in names.pop(addr,[]):
                lines.append(symbol+':')
            lines.append(f"{addr:08x}  {row['op']:02x}  "+render(row,labels))
            counts[row['op']]+=1
            addr=row['next']
        if names or addr!=b['code_end'] or digest(original[b['code_start']:addr])!=b['code_sha256']:
            raise ValueError(f"{name} selector {b['selector']} has incomplete byte or label coverage")
        path=target/f"b{b['selector']:02x}.asm"
        data=('\n'.join(lines)+'\n').encode()
        path.write_bytes(data)
        blocks.append(dict(file=path.relative_to(OUT).as_posix(),sha256=digest(data),selector=b['selector'],
                           source_start=b['code_start'],source_end_exclusive=addr,source_sha256=b['code_sha256'],
                           labels=len(b['labels']),instructions=sum(counts.values())))
    return dict(source_sha256=expected_sha,index_sha256=envelope['sha256'],entries=program['entries'],blocks=blocks)


def main():
    programs={name:export(name,sha) for sha,(name,_) in SOURCES.items()}
    handlers=json.loads((ROOT/'analysis/vm_handlers.json').read_bytes())
    elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if digest(elf)!=handlers['source']['sha256']:
        raise ValueError('Handler map belongs to a different ELF')
    table=['opcode\tfactory_case\tconstructor\tvtable\tdefault_context_entry\tstatus']
    for entry in handlers['opcode_entries']:
        location=entry['factory_table_word']
        if elf[location['file_offset']:location['file_offset']+4].hex()!=location['raw_hex']:
            raise ValueError('Factory dispatch table differs from original ELF')
        table.append('\t'.join(str(entry.get(k) or '-') for k in
                     ('opcode_hex','factory_case','constructor','vtable','default_context_entry','status')))
    (OUT/'dispatch.tsv').write_text('\n'.join(table)+'\n',encoding='utf-8',newline='\n')
    result=dict(elf_sha256=digest(elf),programs=programs,dispatch_entries=len(table)-1,
                instructions=sum(b['instructions'] for p in programs.values() for b in p['blocks']),
                scope='All framed ScenarioLink instruction bytes in stored SCR blocks. Context-specific execution, indirect targets and runtime reachability are separate.')
    (OUT/'manifest.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
    print(json.dumps({name:sum(b['instructions'] for b in p['blocks']) for name,p in programs.items()}))


if __name__=='__main__':
    main()
