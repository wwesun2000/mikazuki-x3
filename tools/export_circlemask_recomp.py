"""Recover the shared circle-mask transition and bind the two reached retail commands."""
import hashlib
import json
import struct

from generate_sound_recomp import export, pilot

if __name__=='__main__':
    iso=pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    entries=(0x193978,0x193bf0,0x193cb8,0x1944a8)
    run=pilot.generate(iso,pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                       entries=entries,work=pilot.ROOT/'local/pc-core/ps2recomp-circlemask',
                       callback_export=pilot.ROOT/'analysis/ghidra/screen-task-frontiers-v1')
    export(run,entries,'circlemask','export_circlemask_recomp.py')
    elf=(run/'SLPM_664.52').read_bytes()
    if struct.unpack_from('<I',elf,0x205640+122*8-0xff000)[0]!=entries[0]:
        raise ValueError('Unbound circle-mask dispatch')
    sites=[]
    for scene,receipt,sha in (
        ('sn2','media-sn2-01/sn2-cold-100000.json','0c157bd95b8d87d8aae608b671807b392de07af2e3d1a38000bcb735f598f17e'),
        ('sn4','slide-pc-01/sn4-cold-100000.json','9313675de61d7034bea8eb42727b4ce0738276ff999da292d4d6b954e9f0114e')):
        route=json.loads((pilot.ROOT/'analysis/native-core'/receipt).read_bytes())
        if '0x193978' not in route['error']:
            raise ValueError('Unexpected route frontier')
        script=(pilot.ROOT/f'local/assets/SCENARIO/{scene}.sn4').read_bytes()
        if hashlib.sha256(script).hexdigest()!=sha:
            raise ValueError('Original ScenarioLink bytes differ')
        # Same 64/128 alignment as the source-backed ScriptData loader.
        base=0x4001c0
        if ((base+len(script)+63)&~63)%128:
            base+=64
        pc=route['last']['cursor']-base
        signature=bytes.fromhex('6f190000007a05')
        offset=script.index(signature,pc,pc+128)
        args=struct.unpack_from('>5i',script,offset+len(signature))
        sites.append(dict(scene=scene,route=receipt,tick=route['last']['tick'],script_sha256=sha,
                          command_offset=hex(offset),command_hex=script[offset:offset+27].hex(),arguments=args))
    manifest=pilot.ROOT/'analysis/ps2recomp-circlemask/manifest.json'
    record=json.loads(manifest.read_bytes())
    record.update(generated_header='port/core/circlemask_generated.hpp',
                  player_binding='Native screen task, current and captured fields, indexed smask texture',
                  reached_commands=sites)
    pilot.record(manifest,record)
