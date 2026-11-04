// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
public class ExportReadbackCallees extends GhidraScript {
    @Override public void run() throws Exception {
        if(!"50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160".equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Wrong EE executable");
        // Two tail-called setters are also shared return blocks of other functions.
        // Split only those verified eight bytes in this read-only Ghidra session.
        int[][] setters={{0x16af48,0x1686d0,0x168600},{0x16b668,0x169e58,0x16a950}};
        for(int[] row:setters){
            var at=toAddr(row[1]);
            if(getInt(toAddr(row[0]))!=(0x08000000|(row[1]>>>2)) ||
               getInt(at)!=0x03e00008 || getInt(at.add(4))!=0xac850024)
                throw new IllegalStateException("Changed original setter "+at);
            if(getFunctionAt(at)!=null)continue;
            var body=new AddressSet(at,at.add(7));
            var owner=getFunctionContaining(at);
            if(owner!=null){
                if(!owner.getEntryPoint().equals(toAddr(row[2])) || !owner.getBody().contains(body))
                    throw new IllegalStateException("Unexpected shared return owner at "+at);
                owner.setBody(owner.getBody().subtract(body));
            }
            if(getInstructionAt(at)==null && !disassemble(at))throw new IllegalStateException("Undecodable "+at);
            currentProgram.getFunctionManager().createFunction("FUN_"+at,at,body,SourceType.USER_DEFINED);
        }
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
