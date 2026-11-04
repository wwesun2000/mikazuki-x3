// Execute the generated constant methods on Ghidra's original R5900 image.
// @category Kamaitachi.Evidence
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.regex.*;
import com.google.gson.GsonBuilder;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;

public class EmulateKamaitachiConstantReturns extends GhidraScript {
    private static final String ELF="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static String sha(Path file)throws Exception{
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
    }
    @Override public void run()throws Exception{
        if(!ELF.equalsIgnoreCase(currentProgram.getExecutableSHA256()) || !currentProgram.getLanguageID().toString().equals("r5900:LE:32:default"))
            throw new IllegalArgumentException("Wrong original ELF or processor");
        Path out=Path.of(getScriptArgs()[0]),header=Path.of(getScriptArgs()[1]);Files.createDirectory(out);
        Matcher entries=Pattern.compile("\\{0x([a-f0-9]+),(-?\\d+)\\}").matcher(Files.readString(header));
        List<Object> rows=new ArrayList<>();int samples=0;
        var emu=new EmulatorHelper(currentProgram);
        try{
            while(entries.find()){
                long entry=Long.parseUnsignedLong(entries.group(1),16);
                long expected=Long.parseLong(entries.group(2));
                for(long initial:new long[]{0x26,0xdecafbadL}){
                    final long sentinel=0x1fff000;
                    emu.writeRegister("v0",initial);emu.writeRegister("ra",sentinel);
                    emu.writeRegister("a0",0x123456);emu.writeRegister("a1",initial);
                    emu.writeRegister(emu.getPCRegister(),entry);int steps=0;
                    while(emu.getExecutionAddress().getOffset()!=sentinel){
                        if(++steps>3 || !emu.step(monitor))throw new IllegalStateException("Original return failed at "+entries.group(1));
                    }
                    if(emu.readRegister("v0").longValue()!=expected || emu.readRegister("a0").longValue()!=0x123456 ||
                       emu.readRegister("a1").longValue()!=initial)throw new IllegalStateException("Wrong original return value or clobber");
                    samples++;
                }
                rows.add(Map.of("entry",entries.group(1),"value",expected));
            }
        }finally{emu.dispose();}
        if(rows.isEmpty())throw new IllegalArgumentException("Empty generated header");
        Map<String,Object> result=new LinkedHashMap<>();
        result.put("status","oracle_completed");result.put("source_elf_sha256",ELF);
        result.put("cpp_header_sha256",sha(header));result.put("harness_sha256",sha(getSourceFile().getFile(false).toPath()));
        result.put("original_instruction_runs",samples);result.put("methods",rows);
        Files.writeString(out.resolve("manifest.json"),new GsonBuilder().setPrettyPrinting().create().toJson(result)+"\n",StandardOpenOption.CREATE_NEW);
    }
}
