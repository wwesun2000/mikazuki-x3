// Execute the original leaf 16BD88 on complete original SN4Font files.
// @category Kamaitachi
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

@SuppressWarnings("removal")
public class EmulateKamaitachiFontResource extends GhidraScript {
    private static final String ELF="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private Address at(long value){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);}
    private static String sha(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=3)throw new IllegalArgumentException("Supply new output directory, original ELF, original font directory");
        byte[] elf=Files.readAllBytes(Path.of(args[1]));
        if(!sha(elf).equals(ELF) || !ELF.equalsIgnoreCase(currentProgram.getExecutableSHA256())
                || !"r5900:LE:32:default".equals(currentProgram.getLanguageID().toString()))throw new IllegalStateException("Unexpected program");
        Path output=Path.of(args[0]);
        Files.createDirectory(output);
        String[] names={"sn2","sn4","sn4g"};
        String[] hashes={"396d03ea918799696e06495813c0369c8059b18c1ddf1e74b4d1595b4bb84738",
            "a3dac7e146cc970e4c8ae2c191afa4ffd2592765c0f11e300a66b7ddf12d00c7",
            "c12f602b3716b1dce68d6bdbcb58b45dbe29d67dab0a5ef7dbb35210e3d370b3"};
        List<Object> rows=new ArrayList<>();
        final long entry=0x16bd88,base=0x400000,sentinel=0x300000;
        Function function=currentProgram.getFunctionManager().getFunctionAt(at(entry));
        int length=(int)function.getBody().getNumAddresses();
        byte[] original=Arrays.copyOfRange(elf,(int)entry-0xff000,(int)entry-0xff000+length);
        byte[] loaded=new byte[length];
        if(currentProgram.getMemory().getBytes(at(entry),loaded)!=length || !Arrays.equals(loaded,original))
            throw new IllegalStateException("Function bytes differ from disk");
        for(int index=0;index<names.length;++index) {
            String name=names[index];
            byte[] source=Files.readAllBytes(Path.of(args[2],name+".fnt"));
            String sourceHash=sha(source);
            if(!sourceHash.equals(hashes[index]))throw new IllegalStateException("Font identity mismatch");
            EmulatorHelper emu=new EmulatorHelper(currentProgram);
            try {
                // Ghidra can retain parts of this mutable buffer as page storage.
                emu.writeMemory(at(base),source.clone());
                emu.writeRegister("a0",base);emu.writeRegister("ra",sentinel);
                emu.writeRegister("sp",0x1ff0000L);emu.writeRegister(emu.getPCRegister(),entry);
                int steps=0;
                while(!at(sentinel).equals(emu.getExecutionAddress())) {
                    monitor.checkCancelled();
                    if(++steps>160000 || !function.getBody().contains(emu.getExecutionAddress()))
                        throw new IllegalStateException("Execution escaped the source function");
                    if(!emu.step(monitor))throw new IllegalStateException("Original instruction failed: "+emu.getLastError());
                }
                byte[] resident=emu.readMemory(at(base),source.length);
                rows.add(Map.of("program",name,"source_sha256",sourceHash,"resident_sha256",sha(resident),
                                "source_steps",steps,"resident_bytes",resident.length));
            } finally {emu.dispose();}
        }
        var record=Map.of("status","oracle_completed","source_elf_sha256",ELF,"source_entry","0x0016bd88",
            "source_function_sha256",sha(original),"function_bytes",length,"descriptor_address",base,
            "harness_sha256",sha(Files.readAllBytes(getSourceFile().getFile(false).toPath())),"programs",rows);
        Files.writeString(output.resolve("manifest.json"),new GsonBuilder().setPrettyPrinting().create().toJson(record)+"\n",StandardOpenOption.CREATE_NEW);
    }
}
