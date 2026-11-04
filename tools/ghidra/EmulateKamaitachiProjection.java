// Execute the original EE tangent, screen clipping and sector discriminator.
// @category Kamaitachi.Evidence
import java.nio.*;
import java.nio.file.*;
import java.math.BigInteger;
import java.util.*;
import com.google.gson.GsonBuilder;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class EmulateKamaitachiProjection extends GhidraScript {
    private Address at(long v){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v);}
    private static byte[] fl(float v){return ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putFloat(v).array();}
    private float value(EmulatorHelper e,int a){return ByteBuffer.wrap(e.readMemory(at(a),4)).order(ByteOrder.LITTLE_ENDIAN).getFloat();}
    private int readReg(EmulatorHelper e,String n){return e.readRegister(n).intValue();}
    private static final int point=0x1401000,ret=0x1fff000;
    private int runEE(EmulatorHelper e,int entry,float angle,Float sectorY)throws Exception{
        e.writeRegister("sp",0x1eff000);e.writeRegister("gp",0x23daf0);e.writeRegister("ra",ret);e.writeRegister("a0",point);
        e.writeRegister("f12",BigInteger.valueOf(Integer.toUnsignedLong(Float.floatToRawIntBits(angle))));
        e.writeRegister(e.getPCRegister(),entry);
        for(int steps=0;steps<13000;steps++){
            int pc=(int)e.getExecutionAddress().getOffset();if(pc==ret)return steps;
            if(pc==0x1925f8 && sectorY!=null){
                int dest=readReg(e,"a0");e.writeMemory(at(dest),fl(320));e.writeMemory(at(dest+4),fl(sectorY));
                e.writeRegister(e.getPCRegister(),e.readRegister("ra"));continue;
            }
            if(!e.step(monitor))throw new IllegalStateException("EE emulation stopped at "+Integer.toHexString(pc));
        }
        throw new IllegalStateException("EE step limit exceeded");
    }
    public void run()throws Exception{
        String elf="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
        if(!elf.equalsIgnoreCase(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Wrong ELF");
        var clip=new ArrayList<Object>();var sectors=new ArrayList<Object>();var e=new EmulatorHelper(currentProgram);
        var result=new LinkedHashMap<String,Object>();
        try{
            int steps=runEE(e,0x1f08f0,value(e,0x237d74),null);
            result.put("original_tangent_bits",Integer.toUnsignedLong(readReg(e,"f0")));result.put("tangent_steps",steps);
            for(float x:new float[]{-1200,-1,0,120,320,640,641,1350})for(float y:new float[]{-800,-1,0,112,224,225,800}){
                e.writeMemory(at(point),fl(x));e.writeMemory(at(point+4),fl(y));runEE(e,0x192478,0,null);
                clip.add(List.of(x,y,value(e,point),value(e,point+4)));
            }
            for(float angle:new float[]{-3,-1,0,1,3})for(float y:new float[]{-1,0,.25f,112,223.75f,224,225}){
                runEE(e,0x192810,angle,y);sectors.add(List.of(angle,y,readReg(e,"v0")));
            }
        }finally{e.dispose();}
        result.put("status","oracle_completed");result.put("elf_sha256",elf);result.put("clip",clip);result.put("sectors",sectors);
        result.put("sector_boundary","1925F8 supplies the specified y to 192810; 192478 and 1F08F0 execute all their own instructions.");
        var out=Path.of(getScriptArgs()[0]);Files.createDirectory(out);
        Files.writeString(out.resolve("manifest.json"),new GsonBuilder().setPrettyPrinting().create().toJson(result)+"\n",StandardOpenOption.CREATE_NEW);
    }
}
