// Compare both original three-work choice routines with the host selection rules.
// @category Kamaitachi.Evidence
import java.nio.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class EmulateKamaitachiTitleSelection extends GhidraScript {
    private Address at(long v){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);}
    private static byte[] word(int v){return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array();}
    private int read(EmulatorHelper e,int a){return ByteBuffer.wrap(e.readMemory(at(a),4)).order(ByteOrder.LITTLE_ENDIAN).getInt();}
    @Override public void run()throws Exception{
        String hash="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
        if(!hash.equalsIgnoreCase(currentProgram.getExecutableSHA256()) || !currentProgram.getLanguageID().toString().equals("r5900:LE:32:default"))
            throw new IllegalArgumentException("Wrong source ELF or R5900 language");
        final int object=0x1401000,sentinel=0x1fff000;
        var samples=new ArrayList<Object>();
        var e=new EmulatorHelper(currentProgram);
        try{
            for(int routine:new int[]{0x108d58,0x10a000})for(int row=0;row<3;++row)for(int key:new int[]{0,0x10,0x40,0x2000,0x100,0x4000,0x400,0x2010,0x2040}){
                int table=routine==0x108d58?0x228648:0x2289c8;
                e.writeMemory(at(object+4),word(table));e.writeMemory(at(object+8),word(row));e.writeMemory(at(object+16),word(3));
                e.writeRegister("sp",0x1eff000);e.writeRegister("gp",0x23daf0);e.writeRegister("ra",sentinel);
                e.writeRegister("a0",0);e.writeRegister("a1",object);e.writeRegister(e.getPCRegister(),routine);
                int sounds=0,polls=0,steps=0;
                while(e.getExecutionAddress().getOffset()!=sentinel){
                    if(++steps>280)throw new IllegalStateException("Title selection exceeded instruction budget");
                    long pc=e.getExecutionAddress().getOffset();
                    if(pc==0x170658){
                        ++polls;e.writeMemory(at(e.readRegister("a1").longValue()),new byte[]{(byte)key,(byte)(key>>8)});
                        e.writeRegister("v0",1);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));
                    }else if(pc==0x1b15f0){++sounds;e.writeRegister("v0",0);e.writeRegister(e.getPCRegister(),e.readRegister("ra"));}
                    else if(!e.step(monitor))throw new IllegalStateException("Emulation failed at "+Long.toHexString(pc));
                }
                int focus=Math.max(0,Math.min(2,row+((key&0x10)!=0?-1:(key&0x40)!=0?1:0)));
                boolean confirm=(key&0x2100)!=0,cancel=(key&0x4400)!=0;
                int expected=confirm?new int[]{2,0,1}[focus]:3;
                if(polls!=1 || read(e,object+8)!=focus || read(e,object+16)!=expected || e.readRegister("v0").intValue()!=(confirm || cancel?0:1))
                    throw new IllegalStateException("Original title selection differs from host rules");
                samples.add(Map.of("routine",Integer.toHexString(routine),"initial_focus",row,"buttons",key,"focus",focus,
                    "result_mode",expected,"sounds",sounds));
            }
        }finally{e.dispose();}
        Path out=Path.of(getScriptArgs()[0]);Files.createDirectory(out);
        String harness=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(getSourceFile().getFile(false).toPath())));
        var result=Map.of("status","oracle_completed","source_elf_sha256",hash,"harness_sha256",harness,"samples",samples,
            "boundaries",List.of("170658 supplies one real controller mask","1B15F0 menu sounds counted at their original call"));
        Files.writeString(out.resolve("manifest.json"),new GsonBuilder().setPrettyPrinting().create().toJson(result)+"\n",StandardOpenOption.CREATE_NEW);
    }
}
