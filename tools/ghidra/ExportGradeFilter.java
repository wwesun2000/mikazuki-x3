// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
public class ExportGradeFilter extends GhidraScript {
    public void run() throws Exception {
        if(!currentProgram.getExecutableSHA256().equalsIgnoreCase("50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160"))
            throw new IllegalStateException("Wrong ELF");
        int[][] callbacks={{0x181300,0x179c40,0x1814c0},{0x181310,0x179c48,0x181660},
            {0x181320,0x179c58,0x1819b8},{0x181330,0x179c50,0x181858}};
        for(int[] c:callbacks){
            if(getInt(toAddr(c[0]))!=(0x0c000000|(c[1]>>2)) ||
               getInt(toAddr(c[0]+4))!=(0x24a50000|(c[2]&65535)))throw new IllegalStateException("Unbound callback");
            var addr=toAddr(c[2]);
            if(getFunctionAt(addr)==null){
                if(getFunctionContaining(addr)!=null)throw new IllegalStateException("Overlapping callback");
                disassemble(addr);
                if(createFunction(addr,null)==null)throw new IllegalStateException("Cannot recover callback");
            }
        }
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
