"""Bind a source media request to immutable SPK dependencies and later cue events.

Read-only evidence/adapter input; does not execute a loader, change presentation,
or acknowledge an active native backend request. No scene-name special cases.
"""
import argparse
import json
from pathlib import Path
import struct
import zipfile

from cue_registry import lookup as cue_id
from scenario_cues import parse_program, callback_arguments, UnresolvedCue
from scenario_resources import ROOT, ResourceIndex, sha, require
from scenario_media_binding import read_types
from vm_handlers import Image


def descriptor_bytes(names):
    require(len(names) < 32768, 'Descriptor count outside positive signed16 range')
    encoded = []
    for name in names:
        raw = name.encode('ascii')
        require(raw and b'\0' not in raw, 'Empty or NUL-containing dependency')
        encoded.append(raw + b'\0')
    return struct.pack('<H', len(names)) + b''.join(encoded)


def bind_descriptor(memory, address, names):
    """Check entire immutable count/name region at the supplied guest address."""
    expected = descriptor_bytes(names)
    require(isinstance(address, int) and 0 < address <= len(memory) - len(expected), 'Descriptor outside guest RAM')
    actual = bytes(memory[address:address + len(expected)])
    require(actual == expected, 'Guest descriptor differs from exact SPK dependency group')
    return dict(address=f'0x{address:08x}', length=len(actual), raw_hex=actual.hex(),
                sha256=sha(actual), source_group_matches=True)


def cue_events(index, cue):
    """Raw source parameters and delayed callbacks; END stays a required callback."""
    raw = bytes.fromhex(cue['raw_hex'])
    base = dict(name=cue['name'], source_sha256=sha(raw), raw_hex=raw.hex(),
                script_e0_index=cue_id(index, cue['name']),
                triggered_by='later explicit opcode74 activation, never by opcode72')
    try:
        commands = parse_program(raw)
        events = []
        for command in commands:
            values = command['values']
            event = dict(command=command['name'], opcode=command['opcode'],
                         program_relative_offset=command['offset'], raw_hex=command['raw_hex'],
                         callback_address=command['callback_address'],
                         arguments=callback_arguments(command),
                         delay_ticks=values['delay_ticks'],
                         time_unit='original cue scheduler ticks; no wall-clock conversion applied',
                         completion_parameter=values['completion_parameter'])
            if command['opcode'] == 1:
                event['requires'] = 'original END stateful cleanup contract; not an implicit NOP'
            if command['opcode'] == 7:
                event.update(encoded_filename=values['filename'],
                             media_source='prepared primary buffer; callback argument is zero')
            if command['opcode'] == 0x14:
                event['asset'] = index.asset(values['filename'])
            if command['opcode'] in (0x0c, 0x0d, 0x10):
                event['original_sound_id'] = values['sound_id']
                event['sound_scope'] = 'source voice identity; STOP/CHANGE do not load a new sound'
                if command['opcode'] == 0x0c:
                    event['asset'] = index.asset(f"{values['sound_id']:06d}")
            events.append(event)
        return dict(**base, status='parsed-source-events-not-executed', events=events)
    except (UnresolvedCue, ValueError) as error:
        return dict(**base, status='blocked-unresolved-cue', error=str(error))


def build_contract(token, root=ROOT, memory=None, descriptor=None):
    root = Path(root)
    index = ResourceIndex.from_project(root)
    image = Image((root / 'local/extracted/SLPM_664.52').read_bytes())
    match = index.resolve(0x72, token)
    names = [d['name'] for d in match['scene']['dependencies']]
    table = {r['extension']: r for r in read_types(image) if r['extension']}
    dependencies = []
    for name, asset in zip(names, match['assets'], strict=True):
        type_ = table.get(name.rsplit('.', 1)[-1]) if asset['kind'] == 'file' else None
        dependencies.append(dict(original_name=name, asset=asset,
                                 source_type=type_,
                                 classification='source-extension-table' if type_ else 'bank-id-or-unresolved-type',
                                 substitution_resolved=bool(type_ and not type_['replacement_extension'])))
    raw_descriptor = descriptor_bytes(names)
    result = dict(schema=1, kind='source-media-request-contract', token=token,
                  sources=dict(elf_sha256=image.sha256, spk_sha256=index.spk_sha256),
                  spk_block=match['spk_block'],
                  dependency_group_absolute_offset=match['spk_block_absolute_offset'] + match['scene']['dependency_group_offset'],
                  descriptor=dict(raw_hex=raw_descriptor.hex(), sha256=sha(raw_descriptor)),
                  dependencies=dependencies,
                  cues=[cue_events(index, c) for c in match['scene']['cues']],
                  active_request=dict(entry='0x001375d8', source_call='0x001376b8',
                      operation='prepare scene dependencies', changes_display=False,
                      next_dependencies=['1384B0 classify/resolve/sort resource list',
                                         '146768 and original active audio preservation/cleanup sequence',
                                         '1378B0 request preparation with retained voice IDs']),
                  status='source-bound-plan-active-native-backend-still-required',
                  limitations=['Does not execute 1384B0 or its original dependency resolver and asynchronous workers.',
                               'No source filename substitution, sorting, fallback, decode-completion or audio success is invented.',
                               'Cue metadata is available to a later explicit activation; preparing resources does not play it.',
                               'Audio IDs, raw parameters, callback ordering and delay ticks are retained; backend mixing remains separate.',
                               'Only dependency bytes are compared with a snapshot; runtime cue trailers/pointers have relocation writes.'])
    if memory is not None:
        result['guest_binding'] = bind_descriptor(memory, descriptor, names)
    else:
        require(descriptor is None, 'A guest descriptor address requires guest memory')
    return result


def from_walk(path, root=ROOT):
    """Consume an existing native failure report and verify its original snapshot."""
    from inspect_pcsx2_states import elf_sections
    root, path = Path(root), Path(path)
    walk = json.loads(path.read_text(encoding='utf-8'))
    require(walk['kind'] == 'original-state-native-context-experiment', 'Unexpected walk report kind')
    candidates = [r for r in walk['trace'] if 'media_descriptor' in r and 'media_token_hex' in r]
    require(len(candidates) == 1, 'Need exactly one explicit media boundary in walk report')
    event = candidates[0]
    require(event['status'] == 'blocked' and event['full_ram_rolled_back'], 'Walk did not safely roll back media boundary')
    observed = json.loads((root / 'analysis/observations/OBS-001/state-analysis/report.json').read_text(encoding='utf-8'))
    state = next(s for s in observed['states'] if s['slot'] == walk['slot'])
    archive_path = root / state['archive']
    require(sha(archive_path.read_bytes()) == walk['archive_sha256'] == state['archive_sha256'], 'Snapshot archive changed')
    with zipfile.ZipFile(archive_path) as archive:
        require(archive.getinfo('eeMemory.bin').file_size == 32 * 1024 * 1024, 'Unexpected original RAM size')
        memory = archive.read('eeMemory.bin')
    require(sha(memory) == walk['ram_sha256'], 'Snapshot RAM changed')
    elf = (root / 'local/extracted/SLPM_664.52').read_bytes()
    require(sha(elf) == walk['elf_sha256'], 'Walk used a different source ELF')
    section = next(s for s in elf_sections(elf) if s['name'] == '.text')
    require(memory[section['address']:section['address'] + section['size']] == elf[section['offset']:section['offset'] + section['size']], 'Snapshot machine code differs from source ELF')
    token = bytes.fromhex(event['media_token_hex']).decode('ascii')
    result = build_contract(token, root, memory, int(event['media_descriptor'], 16))
    result['observation'] = dict(walk_report=str(path), walk_report_sha256=sha(path.read_bytes()),
                                 slot=walk['slot'], archive_sha256=walk['archive_sha256'],
                                 ram_sha256=walk['ram_sha256'],
                                 note='Snapshot validates source request only; no snapshot dependency in intended native runtime.')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--token')
    group.add_argument('--walk', type=Path, help='Existing original-state native walk report; ZIP/ZSTD requires Python3.14')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = from_walk(args.walk) if args.walk else build_contract(args.token)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(output=str(args.output), token=result['token'], dependencies=len(result['dependencies']),
                          cues=len(result['cues']), status=result['status'])))


if __name__ == '__main__':
    main()
