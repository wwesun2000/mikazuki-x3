// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;

public class ExportAnswerMethods extends GhidraScript {
    @Override public void run() throws Exception {
        if(!"50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160".equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Wrong original ELF");
        for(int[] row:new int[][]{{0x11cbc0,0x2236d0},{0x11d018,0x2236f8},
                                  {0x11d5b0,0x223720},{0x11d840,0x223748}}){
            if(getInt(toAddr(row[0]+28))!=(0x25ef0000|(row[1]&0xffff)))throw new IllegalStateException("Changed constructor");
            for(int n=0;n<7;n++){
                var entry=toAddr(getInt(toAddr(row[1]+4*n)));
                if(getFunctionAt(entry)!=null)continue;
                if(getFunctionContaining(entry)!=null || (getInstructionAt(entry)==null && !disassemble(entry)) ||
                   createFunction(entry,"FUN_"+entry)==null)throw new IllegalStateException("Cannot define "+entry);
            }
        }
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
