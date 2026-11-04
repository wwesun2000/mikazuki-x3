// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
public class ExportMysteryPanels extends GhidraScript {
    @Override public void run() throws Exception {
        if(!"50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160".equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Wrong EE executable");
        int tail=getInt(toAddr(0x14ccc4));
        if(tail>>>26!=2 || ((tail&0x3ffffff)<<2)!=0x10c730)throw new IllegalStateException("Changed memory panel tail");
        var target=toAddr(0x10c730);
        if(getFunctionAt(target)==null && (getFunctionContaining(target)!=null ||
           getInstructionAt(target)==null && !disassemble(target) || createFunction(target,"FUN_0010c730")==null))
            throw new IllegalStateException("Cannot define memory panel caption");
        for(int[] descriptor:new int[][]{
                {0x22c218,0x14a0c8,0x14a270,0x14a280,0x14b020,0x14a278},
                {0x22c490,0x14bda8,0x14be38,0x14be48,0x14cb80,0x14be40},
                {0x207488,0x148e60,0x148e88,0x148ea8,0x148ec8,0x148ea0}}){
            for(int slot=1;slot<descriptor.length;slot++){
                int address=descriptor[slot];
                if(getInt(toAddr(descriptor[0]+4*(slot-1)))!=address)
                    throw new IllegalStateException("Changed panel callback table");
                var at=toAddr(address);
                if(getFunctionAt(at)!=null)continue;
                if(getFunctionContaining(at)!=null || getInstructionAt(at)==null && !disassemble(at) ||
                   createFunction(at,String.format("FUN_%08x",at.getOffset()))==null)
                    throw new IllegalStateException("Cannot define panel callback at "+at);
            }
        }
        for(int[] pair:new int[][]{{0x14a060,0x14a06c},{0x14b084,0x14b08c},{0x14ccdc,0x14cce0}}){
            int hi=getInt(toAddr(pair[0])),lo=getInt(toAddr(pair[1]));
            if(hi>>>16!=0x3c04 || lo>>>16!=0x2484)throw new IllegalStateException("Changed queued callback");
            var at=toAddr((hi<<16)+(short)lo);
            if(getFunctionAt(at)==null && (getFunctionContaining(at)!=null ||
               getInstructionAt(at)==null && !disassemble(at) || createFunction(at,String.format("FUN_%08x",at.getOffset()))==null))
                throw new IllegalStateException("Cannot define queued callback "+at);
        }
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
