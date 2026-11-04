// Verify the PANEL/hrsel.dat descriptor of the original executable.
// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public class ExportKamaitachiActorPanel extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        byte[] elf=Files.readAllBytes(Path.of(args[1]));
        String sha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(elf));
        if(!sha.equals("50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160") ||
           !sha.equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("ELF identity mismatch");
        ByteBuffer bytes=ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        int[][] methods={{0,0x14b120},{4,0x14b290},{8,0x14b2a0},{12,0x14bc40},{16,0x14b298}};
        for(int[] method:methods){
            int table=0x22c378+method[0],target=method[1];
            Address entry=toAddr(target);
            if(bytes.getInt(table-0xff000)!=target || getInt(toAddr(table))!=target ||
               getInt(entry)!=bytes.getInt(target-0xff000))throw new IllegalStateException("Source vtable mismatch");
            if(getFunctionAt(entry)==null){
                if(getFunctionContaining(entry)!=null)throw new IllegalStateException("Conflicting function at "+entry);
                disassemble(entry);
                if(createFunction(entry,null)==null)throw new IllegalStateException("Cannot establish "+entry);
            }
        }
        runScript("ExportKamaitachiEvidence.java",args);
    }
}
