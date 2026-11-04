// Validate an explicitly enhanced oracle engine; never patch program bytes/language.
// @category Kamaitachi.Evidence
import java.math.BigInteger;
import java.nio.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.*;

@SuppressWarnings("removal")
public class ValidateKamaitachiMmi extends GhidraScript {
    private static final String SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private final Gson gson=new GsonBuilder().setPrettyPrinting().create();
    private static Map<String,Object> obj(Object...x){Map<String,Object>m=new LinkedHashMap<>();for(int i=0;i<x.length;i+=2)m.put((String)x[i],x[i+1]);return m;}
    private Address at(long x){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x);}
    private void need(boolean x,String s){if(!x)throw new IllegalStateException(s);}
    private static byte[] little(BigInteger v){byte[]r=new byte[16];for(int i=0;i<16;i++)r[i]=v.shiftRight(i*8).byteValue();return r;}
    private static BigInteger big(byte[] v){byte[]r=v.clone();for(int i=0;i<8;i++){byte b=r[i];r[i]=r[15-i];r[15-i]=b;}return new BigInteger(1,r);}
    // Independent byte/word reference implementation (separate from BigInteger lane arithmetic).
    private byte[] reference(String name,byte[]a,byte[]b){
        byte[]r=new byte[16];
        if(name.equals("_pcpyld")){System.arraycopy(b,0,r,0,8);System.arraycopy(a,0,r,8,8);}
        else if(name.equals("_pcpyud")){System.arraycopy(a,8,r,0,8);System.arraycopy(b,8,r,8,8);}
        else if(name.equals("_psubw")){ByteBuffer x=ByteBuffer.wrap(a).order(ByteOrder.LITTLE_ENDIAN),y=ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN),z=ByteBuffer.wrap(r).order(ByteOrder.LITTLE_ENDIAN);for(int i=0;i<4;i++)z.putInt(i*4,x.getInt(i*4)-y.getInt(i*4));}
        else for(int i=0;i<16;i++)r[i]=(byte)(name.equals("_psubb")?a[i]-b[i]:name.equals("_pand")?a[i]&b[i]:a[i]|b[i]);
        return r;
    }
    @Override public void run()throws Exception{
        String[]args=getScriptArgs();Path out=Paths.get(args[0]);Files.createDirectories(out);
        Map<String,Object>manifest=obj("schema",1,"engine","Ghidra EmulatorHelper 12.1.4 plus isolated KamaitachiMmiUserops","status","started","original_ghidra_support",false,"program_mutations",List.of());
        List<Object>cases=new ArrayList<>();
        try{
            byte[]elf=Files.readAllBytes(Paths.get(args[1]));String sha=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(elf));need(SHA.equals(sha),"ELF SHA");
            manifest.put("source_sha256",sha);manifest.put("language",currentProgram.getLanguageID().toString());
            byte[]source=Arrays.copyOfRange(elf,0x1fda0c-0xff000,0x1fdb50-0xff000),actual=new byte[source.length];currentProgram.getMemory().getBytes(at(0x1fda0c),actual);need(Arrays.equals(source,actual),"strcmp source mismatch");
            Random random=new Random(0x524d4d49);int arithmetic=0;
            for(String name:KamaitachiMmiUserops.NAMES)for(int i=0;i<512;i++){
                byte[]a=new byte[16],b=new byte[16];random.nextBytes(a);random.nextBytes(b);
                if(i<256){Arrays.fill(a,(byte)i);Arrays.fill(b,(byte)(255-i));}if(i==256)Arrays.fill(a,(byte)0);if(i==257)Arrays.fill(b,(byte)0);
                need(Arrays.equals(reference(name,a,b),little(KamaitachiMmiUserops.evaluate(name,big(a),big(b)))),"lane vector "+name+" "+i);arithmetic++;
            }
            manifest.put("independent_lane_vectors_passed",arithmetic);
            Map<String,Long>totals=new LinkedHashMap<>();for(String n:KamaitachiMmiUserops.NAMES)totals.put(n,0L);
            int id=0;
            for(int alignment:new int[]{0,1,7,8,15})for(int length:new int[]{0,1,7,8,15,16,17,31,32,63,127})for(int variant=0;variant<5;variant++){
                byte[]a=new byte[160],b=new byte[160];for(int i=0;i<length;i++)a[i]=b[i]=(byte)(1+random.nextInt(255));
                if(variant>0&&length>0){int pos=variant==1?0:variant==2?length/2:length-1;b[pos]=(byte)(variant==4?0:(a[pos]&255)==255?1:(a[pos]&255)+1);}
                int expected=0;for(int i=0;i<a.length;i++){expected=(a[i]&255)-(b[i]&255);if(expected!=0||a[i]==0)break;}
                long left=0x1f00000+alignment,right=0x1f01000+alignment;
                EmulatorHelper e=new EmulatorHelper(currentProgram);KamaitachiMmiUserops mmi=new KamaitachiMmiUserops(e);List<String>faults=new ArrayList<>();
                try{
                    e.setMemoryFaultHandler(new MemoryFaultHandler(){public boolean unknownAddress(Address p,boolean w){faults.add(p.toString());return false;}public boolean uninitializedRead(Address p,int n,byte[]x,int o){faults.add(p.toString());return false;}});
                    for(ghidra.program.model.lang.Register reg:currentProgram.getLanguage().getRegisters())if(reg.isBaseRegister()&&!reg.isProcessorContext())e.writeRegister(reg,BigInteger.ZERO);
                    e.writeMemory(at(left),a);e.writeMemory(at(right),b);e.writeMemory(at(0x1f0f000),new byte[256]);
                    e.writeRegister("a0",left);e.writeRegister("a1",right);e.writeRegister("sp",0x1f0f080);e.writeRegister("ra",0x1fffff0);e.writeRegister(e.getPCRegister(),0x1fda0c);
                    int steps=0;for(;steps<2048&&e.getExecutionAddress().getOffset()!=0x1fffff0;steps++){long pc=e.getExecutionAddress().getOffset();need(pc>=0x1fda0c&&pc<0x1fdb50,"strcmp escaped");need(e.step(monitor),"strcmp error "+e.getLastError());}
                    int returned=e.readRegister("v0").intValue();need(e.getExecutionAddress().getOffset()==0x1fffff0&&returned==expected&&faults.isEmpty(),"strcmp mismatch "+id+" expected "+expected+" actual "+returned);
                    need(Arrays.equals(a,e.readMemory(at(left),a.length))&&Arrays.equals(b,e.readMemory(at(right),b.length)),"input modified");
                    for(String n:totals.keySet())totals.put(n,totals.get(n)+mmi.counts.get(n));
                    cases.add(obj("id",id++,"alignment",alignment,"length",length,"variant",variant,"a_hex",HexFormat.of().formatHex(a),"b_hex",HexFormat.of().formatHex(b),"expected",expected,"actual",returned,"steps",steps,"status","passed","userops",mmi.counts));
                }finally{e.dispose();}
            }
            need(totals.get("_pcpyld")>0&&totals.get("_pcpyud")>0&&totals.get("_psubb")>0&&totals.get("_psubw")>0&&totals.get("_pand")>0,"required MMI coverage");
            manifest.put("strcmp_cases_passed",cases.size());manifest.put("executed_userops",totals);manifest.put("status","mmi_validation_completed");
        }catch(Throwable t){manifest.put("status","failed");manifest.put("error",t.toString());throw t;}
        finally{Files.writeString(out.resolve("cases.json"),gson.toJson(cases));Files.writeString(out.resolve("manifest.json"),gson.toJson(manifest));}
    }
}
