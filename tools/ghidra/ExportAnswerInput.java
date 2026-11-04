// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

public class ExportAnswerInput extends GhidraScript {
    private void inspect(int start,int end,int count,int... tables) throws Exception {
        Function fn=getFunctionAt(toAddr(start));
        if(fn==null)throw new IllegalStateException("Missing original function "+toAddr(start));
        for(int table:tables)for(int i=0;i<count;i++){
            int pc=getInt(toAddr(table+4*i));
            if(pc<start || pc>=end || (pc&3)!=0)throw new IllegalStateException("Invalid target "+toAddr(pc));
            if(getInstructionAt(toAddr(pc))==null)disassemble(toAddr(pc));
        }
        for(int pc=start;pc<end;pc+=4){
            Address address=toAddr(pc);
            Function owner=getFunctionContaining(address);
            if(owner!=null && !owner.equals(fn))throw new IllegalStateException("Conflicting owner "+address);
            if(getInstructionAt(address)==null && (!disassemble(address) || getInstructionAt(address)==null))
                throw new IllegalStateException("Undecodable original word "+address);
        }
        fn.setBody(new AddressSet(toAddr(start),toAddr(end-1)));
    }
    @Override public void run() throws Exception {
        if(!"50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160".equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Wrong original ELF");
        inspect(0x11d2e0,0x11d4bc,8,0x22a5b8,0x22a5d8,0x22a5f8,0x22a618);
        inspect(0x179b58,0x179c40,5,0x22eba8);
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
