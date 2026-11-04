// Recover the two eight-way direction tables at 11B980/11BA04 and the
// three local movement helpers they call. Only the disposable, read-only
// headless analysis session receives the extra function-body metadata.
// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import java.nio.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;

public class ExportKamaitachiNameCursor extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        byte[] elf=Files.readAllBytes(Path.of(args[1]));
        String sha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(elf));
        if(!sha.equals("50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160") ||
           !sha.equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("ELF identity mismatch");
        ByteBuffer bytes=ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        int[] entries={0x11b930,0x11bac0,0x11bc00,0x11bd20,0x11bde0};
        for(int t=0;t<16;++t){
            int address=0x22a558+4*t,target=bytes.getInt(address-0xff000);
            if(getInt(toAddr(address))!=target || target<entries[0] || target>=entries[1] || (target&3)!=0)
                throw new IllegalStateException("Invalid eight-way table at "+toAddr(address));
        }
        for(int i=0;i<4;++i){
            Address entry=toAddr(entries[i]),last=toAddr(entries[i+1]-1);
            for(int pc=entries[i];pc<entries[i+1];pc+=4){
                Address address=toAddr(pc);
                Function previous=getFunctionContaining(address);
                if(previous!=null && !previous.getEntryPoint().equals(entry))
                    throw new IllegalStateException("Overlapping prior function "+previous.getEntryPoint());
                if(getInt(address)!=bytes.getInt(pc-0xff000))throw new IllegalStateException("Different game bytes");
                if(getInstructionAt(address)==null)disassemble(address);
                if(getInstructionAt(address)==null)throw new IllegalStateException("No instruction at "+address);
            }
            Function function=getFunctionAt(entry);
            if(function==null)function=createFunction(entry,null);
            if(function==null)throw new IllegalStateException("No function at "+entry);
            function.setBody(new AddressSet(entry,last));
        }
        runScript("ExportKamaitachiEvidence.java",args);
    }
}
