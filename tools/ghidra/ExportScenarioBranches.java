// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class ExportScenarioBranches extends GhidraScript {
    @Override public void run() throws Exception {
        if(!"50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160".equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Wrong original ELF");
        // The table bounds are the SLTIU 16 at the entry of each switch.
        // The next independently indexed function bounds the last return.
        for(int[] row:new int[][]{{0x100f18,0x100fd8,0x227f80},{0x100fd8,0x101080,0x227fc0}}){
            Function f=getFunctionAt(toAddr(row[0]));
            for(int n=0;n<16;n++){
                int pc=getInt(toAddr(row[2]+4*n));
                if((pc&3)!=0 || pc<row[0] || pc>=row[1])throw new IllegalStateException("Invalid original switch table");
                if(getInstructionAt(toAddr(pc))==null)disassemble(toAddr(pc));
            }
            for(int pc=row[0];pc<row[1];pc+=4){
                Address a=toAddr(pc);
                Function owner=getFunctionContaining(a);
                if(owner!=null && !owner.equals(f))throw new IllegalStateException("Overlapping function "+a);
                if(getInstructionAt(a)==null && (!disassemble(a) || getInstructionAt(a)==null))
                    throw new IllegalStateException("Missing R5900 instruction "+a);
            }
            f.setBody(new AddressSet(toAddr(row[0]),toAddr(row[1]-1)));
        }
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
