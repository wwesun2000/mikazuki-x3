// Read f0 after the original EE pitch conversion, including the signed DIV and its delay slots.
// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import com.google.gson.GsonBuilder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.*;

public class TraceOriginalPitch extends GhidraScript {
    public void run() throws Exception {
        String sha="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
        if(!sha.equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Unexpected ELF");
        List<Object> rows=new ArrayList<>();
        for(int input:new int[]{-1200,-101,-100,-99,-50,-1,0,1,50,99,100,101,1200}){
            EmulatorHelper e=new EmulatorHelper(currentProgram);
            try{
                e.writeRegister("ra",0x3ff000);e.writeRegister("a0",(long)input);
                e.writeRegister(e.getPCRegister(),0x1b0d38);
                int steps=0;
                while(e.getExecutionAddress().getOffset()!=0x3ff000){
                    if(++steps>512 || !e.step(monitor))throw new IllegalStateException("Pitch did not return for "+input);
                }
                int bits=e.readRegister("f0").intValue();
                rows.add(Map.of("operand",input,"steps",steps,"f0_bits",String.format("%08x",bits),
                                "pitch_multiplier",Float.intBitsToFloat(bits)));
                if(input==-50 && bits!=0x3f800000)throw new IllegalStateException("kytr1273_30 result differs");
            }finally{e.dispose();}
        }
        Map<String,Object> result=Map.of("status","passed","elf_sha256",sha,"function","0x1B0D38",
            "scope","Original EE instructions in Ghidra, no stubs; isolated pitch conversion, not a mixer or scene comparison",
            "cases",rows);
        Files.writeString(Path.of(getScriptArgs()[0]),new GsonBuilder().setPrettyPrinting().create().toJson(result)+"\n",
                          StandardOpenOption.CREATE_NEW);
    }
}
