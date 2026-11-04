// @category Kamaitachi.Evidence
import java.nio.file.*;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;

public class ObserveCardMessages extends GhidraScript {
    public void run() throws Exception {
        final String sha="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
        if(!currentProgram.getExecutableSHA256().equalsIgnoreCase(sha))throw new IllegalArgumentException("Wrong ELF");
        var result=new ArrayList<Object>();
        var emu=new EmulatorHelper(currentProgram);
        try {
            for(int id=0;id<40;++id){
                emu.writeRegister("a0",0x1800000);emu.writeRegister("a1",id);
                emu.writeRegister("ra",0x1fff000);emu.writeRegister("gp",0x23daf0);
                emu.writeRegister("sp",0x1f00000);emu.writeRegister(emu.getPCRegister(),0x1a3280);
                var draws=new ArrayList<Object>();
                int steps=0;
                while(emu.getExecutionAddress().getOffset()!=0x1fff000){
                    final long pc=emu.getExecutionAddress().getOffset();
                    if(pc==0x19e638 || pc==0x19e308){
                        long descriptor=emu.readRegister("a1").longValue()&0xffffffffL;
                        draws.add(Map.of("draw",pc,"descriptor",descriptor));
                    }
                    if(++steps>8000 || !emu.step(monitor))throw new IllegalStateException("Card draw failed: "+id+" at "+Long.toHexString(pc));
                }
                result.add(Map.of("message",id,"draws",draws,"instructions",steps));
            }
        }finally{emu.dispose();}
        Path output=Path.of(getScriptArgs()[0]);Files.createDirectories(output);
        Files.writeString(output.resolve("messages.json"),new GsonBuilder().setPrettyPrinting().create().toJson(
            Map.of("elf_sha256",sha,"entry",0x1a3280,"cases",result))+"\n");
    }
}
