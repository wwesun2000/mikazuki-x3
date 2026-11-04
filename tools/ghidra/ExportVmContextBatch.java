// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
public class ExportVmContextBatch extends GhidraScript {
    public void run() throws Exception {
        if(!"50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160".equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Wrong EE executable");
        for(int[] pair:new int[][]{{0x223e94,0x123928},{0x223ec8,0x124500},
                                   {0x223f04,0x124fb0},{0x223f38,0x125440}}){
            if(getInt(toAddr(pair[0]))!=pair[1])throw new IllegalStateException("Changed original vtable");
            var at=toAddr(pair[1]);
            if(getFunctionAt(at)!=null)continue;
            if(getFunctionContaining(at)!=null)throw new IllegalStateException("Another function owns "+at);
            if(getInstructionAt(at)==null && !disassemble(at))throw new IllegalStateException("Cannot disassemble "+at);
            if(createFunction(at,String.format("FUN_%08x",pair[1]))==null)throw new IllegalStateException("Cannot define "+at);
        }
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
