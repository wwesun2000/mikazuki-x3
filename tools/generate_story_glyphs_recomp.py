"""Build original primary/ruby character insertion, glyph-node creation and controller artwork."""
from generate_sound_recomp import export,pilot

entries=(0x16b498,0x16b608,0x169a48,0x168d08,0x168dd0,0x16b6e8,0x16be70,0x16acc0,0x169ad8,
         0x168398,0x1698a0,0x169c70,0x169cb0,0x169218,0x10b290,0x1683b0,0x169e68,0x16b910,
         0x1326e0,0x16b670,0x169ab0,0x168fc0,0x16a420,0x16a428,0x1682f8,0x169e58)

if __name__=="__main__":
    run=pilot.generate(pilot.ROOT/"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso",
                       pilot.EVAL/"ee-pilot/build/ps2xRecomp/ps2_recomp.exe",entries=entries,
                       work=pilot.ROOT/"local/pc-core/ps2recomp-story-glyphs",
                       callback_export={0x1683b0:pilot.ROOT/"analysis/ghidra/glyph-color-vtable-v1",
                                        0x169e58:pilot.ROOT/"analysis/ghidra/readback-font-setter-v1"})
    export(run,entries,"story_glyphs","generate_story_glyphs_recomp.py")
    names={a:next((run/"generated").glob(f"*_0x{a:x}.cpp")).stem for a in entries}
    (pilot.ROOT/"port/core/story_glyphs_entries.hpp").write_text(
        "".join(f"KX3_MENU_ENTRY(0x{a:x},{names[a]})\n" for a in entries),encoding="ascii")
