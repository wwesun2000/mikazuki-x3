// @category Kamaitachi.Evidence
public class ExportSystemCardMenus extends ExportCardResultSwitch {
    public void run() throws Exception {
        if(!currentProgram.getExecutableSHA256().equalsIgnoreCase("50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160"))
            throw new IllegalStateException("Wrong ELF");
        if(getInt(toAddr(0x1a6644))!=0x2c4f0032)
            throw new IllegalStateException("Invalid 50-state memory menu bound");
        for(int pc:new int[]{0x1a7100,0x1a7114,0x1a7134})
            if(getInt(toAddr(pc))!=0x2c4f0033)
                throw new IllegalStateException("Invalid 51-state save-and-quit menu bound");
        bindTable(0x1a6588,0x1a6f40,0x1a6660,0x230ae0,50);
        bindTable(0x1a70d0,0x1a7c88,0x1a7150,0x230c84,51);
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
