// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
public class ExportSceneCue extends GhidraScript {
    @Override public void run() throws Exception {
        if(!"50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160".equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Wrong EE executable");
        // The scheduler receives these original code pointers in t1 and t0.
        for(int[] pair:new int[][]{{0x139700,0x139724,9},{0x13ae34,0x13ae50,8},{0x1b27dc,0x1b27e4,5}}){
            int hi=getInt(toAddr(pair[0])),lo=getInt(toAddr(pair[1])),reg=pair[2];
            if((hi>>>16)!=(0x3c00|reg) || (lo>>>16)!=(0x2400|(reg<<5)|reg))
                throw new IllegalStateException("Unexpected original callback load");
            var at=toAddr((hi<<16)+(short)lo);
            if(getFunctionAt(at)!=null)continue;
            if(getFunctionContaining(at)!=null || getInstructionAt(at)==null && !disassemble(at) ||
               createFunction(at,String.format("FUN_%08x",at.getOffset()))==null)
                throw new IllegalStateException("Cannot define callback at "+at);
        }
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
