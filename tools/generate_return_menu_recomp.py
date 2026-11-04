"""Build the post-scenario menu initializer and its memory-card UI object reset."""
from generate_sound_recomp import export, pilot

entries=(0x100410,0x100ec8,0x102530,0x1025e0,0x104998,0x1061f0,0x106d60,0x106d90,
         0x1074a0,0x10c8f8,0x115c50,0x121980,0x122090,0x1220d0,0x122118,0x163d18,0x19c6b0,
         0x19cfa8,0x19d628,0x19d7f8,0x1a1b18,0x1a2d60,0x1a2d78,0x1a2ed8,0x1a3a28,
         0x1a3cc0,0x1a8728,0x1aad30)

if __name__=='__main__':
    iso=pilot.ROOT/'Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso'
    run=pilot.generate(iso,pilot.EVAL/'ee-pilot/build/ps2xRecomp/ps2_recomp.exe',
                       entries=entries,work=pilot.ROOT/'local/pc-core/ps2recomp-return-menu')
    export(run,entries,'return_menu','generate_return_menu_recomp.py')
    table=''.join(f'KX3_MENU_ENTRY(0x{a:x},FUN_{a:08x}_0x{a:x})\n' for a in entries)
    (pilot.ROOT/'port/core/return_menu_entries.hpp').write_text(table,encoding='ascii')
