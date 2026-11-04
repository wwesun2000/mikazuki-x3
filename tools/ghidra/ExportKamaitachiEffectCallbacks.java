// Recover two indirect callbacks in a temporary transaction. The independently
// verified original instructions bind each entry. The project retains no edits.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;

public class ExportKamaitachiEffectCallbacks extends GhidraScript {
    private static final String SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private Address at(int n){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(n);}
    private void check(int pc,int word)throws Exception{
        if(currentProgram.getMemory().getInt(at(pc))!=word)throw new IllegalArgumentException("Callback site differs: "+at(pc));
    }
    @Override public void run()throws Exception{
        String[] args=getScriptArgs();
        if(!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(Path.of(args[1])))).equals(SHA))
            throw new IllegalArgumentException("Original ELF required");
        check(0x17c568,0x0805f040); // j 17C100
        check(0x17bac0,0x0c05e712);check(0x17bac4,0x24a5c698); // 179C48 draw setter
        check(0x17bad0,0x0c05e716);check(0x17bad4,0x24a5ca80); // 179C58 destructor
        check(0x17ca48,0x12200004);check(0x17ca4c,0x24a5c598);check(0x17ca68,0x0805e710);
        int transaction=currentProgram.startTransaction("Transient original effect callbacks");
        try{
            for(int n:new int[]{0x17c100,0x17c598,0x17c698,0x17ca80}){
                Address a=at(n);
                if(getFunctionAt(a)==null && getFunctionContaining(a)==null){
                    if(!disassemble(a) || createFunction(a,"SOURCE_CALLBACK_"+Integer.toHexString(n))==null)
                        throw new IllegalStateException("Could not establish "+a);
                }
            }
            runScript("ExportKamaitachiEvidence.java",args);
        }finally{currentProgram.endTransaction(transaction,false);}
    }
}
