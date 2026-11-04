// Resolve the original 134-entry, source-byte-indexed lookahead table at
// 22A204 in the chart/chapter jump path. The temporary headless transaction
// covers only the checked 117580 body and leaves the project unmodified.
// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Function;
import java.nio.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;
public class ExportKamaitachiJumpScan extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        byte[] elf=Files.readAllBytes(Path.of(args[1]));
        String sha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(elf));
        if(!sha.equals("50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160") ||
           !sha.equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("ELF identity mismatch");
        ByteBuffer bytes=ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        final int first=0x117580,limit=0x117840;
        for(int i=0;i<134;++i){
            int a=0x22a204+i*4,t=bytes.getInt(a-0xff000);
            if(getInt(toAddr(a))!=t || t<first || t>=limit || (t&3)!=0)throw new IllegalStateException("Invalid opcode-table target");
        }
        for(int p=first;p<limit;p+=4){
            Address a=toAddr(p);Function f=getFunctionContaining(a);
            if(f!=null && !f.getEntryPoint().equals(toAddr(first)))throw new IllegalStateException("Conflicting function "+a);
            if(getInt(a)!=bytes.getInt(p-0xff000))throw new IllegalStateException("ELF differs from analysis memory");
            if(getInstructionAt(a)==null)disassemble(a);
            if(getInstructionAt(a)==null)throw new IllegalStateException("Could not disassemble "+a);
        }
        getFunctionAt(toAddr(first)).setBody(new AddressSet(toAddr(first),toAddr(limit-1)));
        // Actual 1206E8-created context vtable at 223A30. The methods may
        // be absent from Ghidra's original function map.
        for(int i=0;i<4;++i){
            int table=0x223a30+i*4,t=bytes.getInt(table-0xff000);Address a=toAddr(t);
            if(t<0x120760 || t>=0x120850 || getInt(toAddr(table))!=t)throw new IllegalStateException("Invalid context vtable");
            if(getFunctionAt(a)==null && getFunctionContaining(a)==null){disassemble(a);createFunction(a,null);}
        }
        runScript("ExportKamaitachiEvidence.java",args);
    }
}
