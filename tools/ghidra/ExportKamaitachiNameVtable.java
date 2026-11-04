// Source vtable 223698 is installed at the end of the original 11B640
// constructor. Define its four missing method boundaries in a read-only
// analysis session and pass the resulting program to the normal exporter.
// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public class ExportKamaitachiNameVtable extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        byte[] elf=Files.readAllBytes(Path.of(args[1]));
        String sha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(elf));
        if(!sha.equals("50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160") ||
           !sha.equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("ELF identity mismatch");
        ByteBuffer bytes=ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        int[][] methods={{8,0x11bde0},{16,0x11b7e8},{20,0x11bdf8},{24,0x11c628}};
        for(int[] method:methods){
            int table=0x223698+method[0],target=method[1];
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
