"""Produce source/observation-bound choice contracts, without simulating inputs."""
import hashlib
import json
from pathlib import Path
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ELF_SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
STATE_SHA = '46ba269acf9d226ecadfd098e54f38356dda5e4239f3a0579d79a7dcd1860f0f'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hx(n):
    return f'0x{n:08x}'


def build():
    elf = (ROOT/'local/extracted/SLPM_664.52').read_bytes()
    if sha(elf) != ELF_SHA:
        raise ValueError('ELF identity mismatch')
    functions = {}
    for directory in ('choice-runtime-v1','choice-effects-v1','choice-presentation-v1',
                      'choice-transfer-v2','choice-transfer-dependencies-v1'):
        base = ROOT/'analysis/ghidra'/directory
        manifest = json.loads((base/'manifest.json').read_text())
        if manifest['status'] != 'export_completed' or manifest['source_sha256'] != ELF_SHA:
            raise ValueError('Ghidra export identity/status mismatch')
        for file in sorted((base/'functions').glob('*.json')):
            d = json.loads(file.read_text())
            raw = bytearray()
            for unit in d['disassembly']['units']:
                off = unit['canonical_elf_file_offset']
                data = bytes.fromhex(unit['raw_hex'])
                if off is None or elf[off:off+len(data)] != data:
                    raise ValueError('Dossier instruction differs from source ELF')
                raw.extend(data)
            functions[file.stem] = dict(path=str(file.relative_to(ROOT)), sha256=sha(file.read_bytes()),
                                        source_body_bytes=len(raw), source_body_sha256=sha(raw),
                                        decompilation_status=d['decompilation']['status'])
    state_file = ROOT/'analysis/observations/OBS-001/pcsx2/sstates/SLPM-66452 (0D03C0A3).07.p2s'
    if sha(state_file.read_bytes()) != STATE_SHA:
        raise ValueError('OBS-001 slot7 identity mismatch')
    with zipfile.ZipFile(state_file) as archive:
        ram = archive.read('eeMemory.bin')  # Python3.14 ZIP ZSTD, read-only.
    u = lambda a:struct.unpack_from('<I',ram,a)[0]
    manager, choice = u(0x235e40), u(u(0x235e40)+8)
    segments = []
    for name,address,length in [('choice',choice,0x1d4),('callback_registry',0x1e4ab78,16),
                                ('input_device0',0x1e41c60,0x130),('choice_pointer_record2',0x1e44378,0xbc)]:
        raw = ram[address:address+length]
        if len(raw) != length:
            raise ValueError('Incomplete guest slice')
        segments.append(dict(name=name,address=hx(address),size=length,sha256=sha(raw),hex=raw.hex()))
    observed = dict(schema=1,source_archive_sha256=STATE_SHA,source_elf_sha256=ELF_SHA,
                    incomplete_guest_memory=True,memory=segments,
                    dynamic_callbacks={hx(a):hx(u(a)) for a in (0x1e4ab7c,0x1e4ab80)},
                    scope='Original slot7 bytes only; not an executed input transition or native save')
    fixture_path = ROOT/'analysis/choice_runtime_slot7.json'
    fixture_path.write_text(json.dumps(observed,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    fields = [
        ('0x04','option_count',3,'1186E8 stores source count; 117D60/117DB8 bounds'),
        ('0x08','preview_index',2,'118338 records glyph ends and advances template iterator; not focus'),
        ('0x0c','mode',1,'117D00 setter; 117D58 getter'),
        ('0x10','saved_selector',18,'1186E8 saves D0; 118338 restores it'),
        ('0x14','saved_label_id',2839,'1186E8 saves D4; 118338 restores it'),
        ('0x18','saved_relative_cursor',0x3bbb,'1186E8 saves D610(0); points after original6C operands'),
        ('0x1c','target_label_pointer_array',None,'117D28 indexes by focus'),
        ('0x44','target_selector_array',None,'117D40 indexes by focus'),
        ('0x6c','source_flag_bytes',None,'1186E8 source bytes, not a blanket disabled flag'),
        ('0x78','option_x_array',None,'118308 pointer x is selected x minus18'),
        ('0xa0','option_y_array',None,'16CC50 pointer y adds6'),
        ('0xc8','primary_glyph_start_array',None,'1189F8 records current primary count'),
        ('0xf0','primary_glyph_end_inclusive_array',None,'118338 stores primary count minus1'),
        ('0x118','ruby_glyph_start_array',None,'1189F8 records ruby count'),
        ('0x140','ruby_glyph_end_inclusive_array',None,'118338 stores ruby count minus1'),
        ('0x168','focus_index',0,'117D28/117D40 use this; navigation writes this'),
        ('0x16c','saved_font_x',None,'118200 saves and118250 restores'),
        ('0x170','saved_font_y',None,'118200 saves and118250 restores'),
        ('0x18c','scripted_sequence_length',0,'1186E8: extra-byte-count/2'),
        ('0x190','scripted_sequence_confirm',0,'118BF8 sets on signed direction0;118E30 reads'),
        ('0x194','scripted_sequence_enabled',0,'1186E8 extra-byte-count!=0;118E28 reads'),
        ('0x198','scripted_sequence_index',0,'118BF8 advances after countdown'),
        ('0x19c','scripted_direction_bytes',None,'signed negative=Up;positive=Down;zero=confirm'),
        ('0x1b0','scripted_delay_bytes',None,'decrement nonzero delay; process direction once zero'),
        ('0x1c4','saved_context_pointer',0x1e15cc0,'1186E8 saves current context;118E20 reads'),
        ('0x1c8','alternate_context_flag',0,'1186E8 context predicates'),
        ('0x1cc','other_context_flag',0,'1186E8 context predicates'),
        ('0x1d0','special_mode',0,'1186E8; affects read-state color and commit path'),
    ]
    report = dict(schema=1,status='source_contract_and_atomic_context_slice; full_choice_integration_pending',
        elf_sha256=ELF_SHA,source_functions=functions,
        runtime_anchor=dict(archive_sha256=STATE_SHA,manager=hx(manager),choice=hx(choice),
                            context=hx(u(manager+0x40)),vtable=hx(u(u(manager+0x40))),
                            fields=[dict(offset=o,name=n,observed_value=v,evidence=e) for o,n,v,e in fields],
                            fixture_path=str(fixture_path.relative_to(ROOT)),fixture_sha256=sha(fixture_path.read_bytes())),
        input=dict(authority=['0015fe30','0015f168','001173a8','00118bf8','0011e748'],
            sample='15FE30 gates device0 via175E70 then15F168. Device+B4 pending: old=U16(+BA),+B4=0,+BA=U16(+B8),+BC=(~old)&U16(+B8). Return edge+BC. Repeated reads in one update return same edge.',
            normal_navigation=[dict(mask='0x8040',priority=1,action='restore_old_color; if0x40 set increment_clamp else increment_wrap'),
                               dict(mask='0x0010',priority=2,action='restore_old_color; decrement_clamp')],
            recolor_mask='0x8050',confirm_mask='0x2100',
            cross_mask='0x4000 is not tested by normal118BF8/11E748; no choice cancellation inferred',
            left_right='0x0080/0x0020 not navigation in normal118BF8; graphical7F is separate',
            semantic_keys='Raw game masks retained. OBS-001 verifies Up/Down/Circle behavior; no extra physical-button mapping inferred here.',
            overrides=['choice194 script sequence overrides navigation; choice190 controls confirmation in11E748',
                       'manager808 autoplay:115D50 supplies0x8000 cycle or0x2100 confirm; source timer/state updated in core',
                       '11E748 samples confirmation after navigation; simultaneous movement/confirm keeps source order']),
        manager_gate=dict(authority=['00113148','00112f78','001173a8','001165d8','00117ad0'],
            before_choice_context=True,
            conditions=['helper4 mode predicate==0','edges&0x50!=0','helper2 context predicate!=0',
                        'interactive choice: Up eligible only focus==0; Down eligible only focus==count-1'],
            order='mode defaults1; Down=>2; Up=>0 takes precedence. Eligible1165D8 succeeds=>117AD0+return1, otherwise return0 and normal choice update may run.',
            persistent_operations=['save old context and selector/label/relative cursor','history lookup10EAA8(mode0)/10DC30(mode1)/116840(mode2)',
                                   '10F070 push history snapshot','helper04 active/position/repeat fields','real readback context and script cursor transitions'],
            consequence='Down at final choice can attempt read-forward first; OBS-001 no visible change is not proof that the boundary always ignores Down.',
            recovered='134AF0 eligibility and1165D8 ordinary mode0 entry now execute in core; see analysis/choice_readback_recovery.json',
            unresolved=['mode1/2 forward scan and downstream readback context loop','19CCA8 callback must resolve before nonzero execution','Intermediate19C868 notified history walks require source callback recovery']),
        navigation=dict(authority=['00117d60','00117db8','00118308','00118150','00117f68'],
            focus_write='Increment/decrement+168 using32-bit wrapping arithmetic then signed comparison; argument a1 chooses clamp0 or wrap1.',
            after_write=['19CAD8(focus) reads callback01E4AB80; zero means no call, nonzero requires source callback dispatch',
                         '118308 rereads focus and sends pointer position(x[focus]-18,y[focus]+6)'],
            color_restore=dict(core_query='118088 resolves targetID10FA88; if not internal10EFC0 then reads10EFF0 bit28; does not disable option',
                precedence=['recorder115BD8 active => (92,128,128)',
                            '175F78 is a verified constant-zero source stub; read predicate true => (64,64,64)',
                            'otherwise special_mode => (112,64,0)',
                            'otherwise => (128,128,128)']),
            color_highlight='Normal mode (128,64,64); special mode118010 applies it only when118138 read predicate succeeds.',
            mouse_contract='Map hit to original option index; drive same focus update/notification/color/pointer chain, then same confirm. Never transfer directly to target label.'),
        confirmation=dict(authority=['0011e748','00118288','0011e608','00118d68'],
            begin_order=['118150 restore current option color','16CC38 hide pointer','113430 restores manager58 task state/callback',
                         'normal mode117E30 gives every nonfocus primary/ruby range step=-8.0f',
                         '19CAA8(focus): callback01E4AB7C if nonzero','119E70 retires hint task and zeroes object+2C when active',
                         'manager context becomes11EB28 transition singleton'],
            wait='11E608 calls16BA10(font); nonzero blocks, zero calls118D68. Always context return1.',
            commit_order=['118250 restore saved fontXY','117EE8(0) sets selected primary/ruby current=0.0f',
                          'normal mode install default120280 context','10D868(real selected selector,label,flag0), including history/read-state',
                          '11A380 manager28 object+14=1'],
            source_float=dict(address='0x00235e90',raw_hex=elf[0x235e90-0xff000:0x235e94-0xff000].hex(),value=-8.0),
            unresolved=['17D3E0 task callback body lacks a Ghidra function entry; never silently removed',
                        'Nonzero19CAA8 callback dispatch and readback/special contexts remain required']),
        frontend_contract=dict(status='Concrete interface design; no frontend implementation claimed',
            source_owned_state=['count/mode/focus/preview iterator','source option identity/flags/targets','saved source position/context',
                                'history/read/visited predicates and callbacks','scripted sequence/autoplay counters','pending confirm state'],
            presentation_owned_serializable_state=['logical primary/ruby glyph nodes with original stable IDs andinclusive ranges',
                                                   'node RGB,current,step','pointer active/XY','font currentXY','hint/task presentation state'],
            events=[dict(name='glyph_range_color',args=['channel','first','last_inclusive','r','g','b'],source='1689A8 writes node bytes0/1/2 only'),
                    dict(name='glyph_range_step',args=['channel','first','last_inclusive','float32_step'],source='168BC8 writes node+8 only'),
                    dict(name='glyph_range_current',args=['channel','first','last_inclusive','float32_current'],source='168AC8 writes node+4 only'),
                    dict(name='pointer_move',args=['float32_x','float32_y'],source='16CC50/16C898'),
                    dict(name='pointer_hide',args=[],source='16C790 type2 clears active and+4'),
                    dict(name='font_position_restore',args=['x','y'],source='118250->16A950')],
            advance='1697D0 each renderer preparation tick: f32(current+step), clamp at0/128 and clear step at bounds. Keep cadence explicit, not a guessed wall-clock duration.',
            ready='16BA10 checks both entire channels: pending if any step!=0 and current!=(step>0?128:0). An empty/zero-step channel does not block.',
            persistence='A save during confirmation must retain glyph current/step, focus, saved cursor/context and pending task state; cannot acknowledge completion before actual frontend state is ready.',
            errors='Missing registered source callback or unimplemented task dependency blocks before commit; never acknowledge a placeholder as performed.'),
        native_leaf=dict(api='invoke_choice_leaf(GuestMemory&,entry,self,a1)',
                         files=['port/core/choice.hpp','port/core/choice.cpp'],
                         oracle='analysis/ghidra/oracle-choice-v1/manifest.json',oracle_entries=11,oracle_cases=154,
                         untested_entry='0011E828 raw8-byte context slot1 return1; reliable vtable anchor, no created function boundary yet',
                         limits='Leaf accessors/predicates only. Does not provide a usable interactive choice or claim full original VM.'),
        native_pipeline=dict(files=['port/core/choice_pipeline.hpp','port/core/choice_pipeline.cpp'],
            api=['choice_context_atomic','choice_context_transactional','choice_transfer_transactional','choice_readback_gate_atomic','choice_readback_gate_transactional','choice_readback_begin_transactional','choice_readback_eligible','choice_device_edges'],
            ordinary_transfer='10D868 including10ECA0(a2=0),19CB50,10F198 is recovered. Uses original selector/label pointers and history words, not target-label UI jumping.',
            contract_test='analysis/native-core/choice-pipeline-slot7.json',
            backward_entry='Original1165D8 mode0 and134AF0 eligibility recovered;14 original-machine cases match native persistent state and v0.',
            limits='Ordinary manual mode1 choices only. Source callbacks/effects require explicit capabilities; effects publish after guest commit. Forward readback, downstream viewer loop, graphical/special/scripted/autoplay paths remain unavailable. No shipping UI or full game completion claimed.'),
        transfer=dict(function='0x0010d868',
            progress_callback=dict(cell='0x01e4ab88',actual_slot7_value=hx(u(0x1e4ab88)),nonzero='Requires registered original-source execution; no UI-only assumption'),
            chapter='19C4C0 compares2 source bytes against18 original pointer-table prefixes.19C538 reads2 decimal chapter bytes after optional lowercase third name character.19C6B8 checks category<18 and chapter not0/255.',
            retained_name='19C638 copies at most13 bytes; stops on copied NUL, leaves tail unchanged, does not invent a trailing NUL after13 non-NUL bytes.',
            original_default_helper4=dict(target='0x00134d88',raw_hex=elf[0x134d88-0xff000:0x134d90-0xff000].hex(),
                file_offset=0x134d88-0xff000,boundary='Actual vtable target and8 source bytes; missing Ghidra function boundary retained, none created',behavior='JR RA with delay DADDU v0,zero,zero'),
            ordinary_side_effects=['Install selector and source code cursor','Public labels update current label id','Write prior forward link and visited bit','Apply script14C/manager740/recorder744 flags','Unless flag nonzero, write backward link and one-time media id','Apply pending150 saved edge correction','Update source chapter tracker when recording requires it'],
            excluded_auto_save='This call passes10ECA0 a2=0, so117560/104E10 is not called by this transfer path.',
            original_machine_limit='Original base SLEIGH run failed on aligned strcmp _pcpyld at1FDA5C; preserved in oracle-choice-transfer-v1. Enhanced engine with separately audited six-userop implementation returned33/33 using original string layout and declared coverage patches; C++ all persistent state matches33/33. This is not stock Ghidra support or PCSX2 observation.',
            scalar_oracle='analysis/ghidra/oracle-choice-transfer-scalar-v1/manifest.json',
            enhanced_oracle='analysis/ghidra/oracle-choice-transfer-enhanced-v1/manifest.json',
            native_differential='analysis/native-core/choice-transfer-diff.json',
            differences_excluded=['ABI stack because portable C++ uses host stack','Incidental v0 because original10D868 is used as void']),
        remaining_core_work=['Register real source callback dispatch for nonzero callbacks; slot7 two callbacks are actually null',
                             'Implement source scripted sequence/autoplay modes separately; current ordinary pipeline rejects them',
                             'Recover readback gate closure and connect task17D3E0 presentation behavior; preserve source update order',
                             'Connect real renderer state/ready and transactional transfer to root scheduler before enabling choice in product UI'])
    output = ROOT/'analysis/choice_runtime_recovery.json'
    output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(output),source_functions=len(functions),source_bound=True,fixture_guest_bytes=sum(s['size'] for s in segments))))
    return report


if __name__ == '__main__':
    build()
