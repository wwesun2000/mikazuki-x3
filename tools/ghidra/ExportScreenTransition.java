// Establish the five callbacks addressed by the 0x192080 factory in the read-only analysis.
// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public class ExportScreenTransition extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        byte[] elf=Files.readAllBytes(Path.of(args[1]));
        String sha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(elf));
        if(!sha.equals("50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160")
           || !sha.equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("ELF identity mismatch");
        ByteBuffer raw=ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        int[][] methods={{0x1920e4,0x192258},{0x1921fc,0x1928a8},{0x192230,0x193558},
                         {0x192240,0x193008},{0x192250,0x192cb0}};
        for(int[] method:methods){
            int pc=method[0], target=method[1], addiu=0x24a50000|(target&0xffff);
            if(raw.getInt(pc-0xff000)!=addiu || getInt(toAddr(pc))!=addiu)
                throw new IllegalStateException("Unexpected factory instruction at "+Integer.toHexString(pc));
            Address entry=toAddr(target);
            if(getFunctionAt(entry)==null){
                if(getFunctionContaining(entry)!=null)throw new IllegalStateException("Conflicting function at "+entry);
                disassemble(entry);
                if(createFunction(entry,null)==null)throw new IllegalStateException("Cannot establish "+entry);
            }
        }
        runScript("ExportKamaitachiEvidence.java",args);
    }
}
