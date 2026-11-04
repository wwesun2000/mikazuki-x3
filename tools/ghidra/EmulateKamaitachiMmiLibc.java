// Standard native-diff fixtures, original instructions plus explicit MMI userops.
// @category Kamaitachi.Evidence
import java.io.*;
import java.math.BigInteger;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.framework.Application;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

@SuppressWarnings("removal")
public class EmulateKamaitachiMmiLibc extends GhidraScript {
    private static final String SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160",LANG="r5900:LE:32:default";
    private static final long SELF=0x1f00000L,DATA=0x1f02000L,BLOCK=0x1f04000L,OUT=0x1f08000L,STACK=0x1f0ee00L,SP=0x1f0f000L,RETURN=0x1fffff0L,SEED=0x524d4d49L;
    private static final long[] ENTRIES={0x1fda0c,0x1fdb50,0x1fdc64,0x10d4c8,0x10d590,0x10d680,0x10d720,0x10d610};
    private static final String[] REGS={"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","s8","ra"};
    private final Gson pretty=new GsonBuilder().setPrettyPrinting().serializeNulls().create(),compact=new GsonBuilder().serializeNulls().create();
    private final AddressSet allowed=new AddressSet();private final List<long[]>loads=new ArrayList<>();private byte[]elf;private Path output;
    private static Map<String,Object> obj(Object...a){Map<String,Object>r=new LinkedHashMap<>();for(int i=0;i<a.length;i+=2)r.put((String)a[i],a[i+1]);return r;}
    private static String h(long v){return String.format("0x%016x",v);}private static String h32(long v){return String.format("0x%08x",v&0xffffffffL);}
    private static String hex(byte[]b){return HexFormat.of().formatHex(b);}private static String sha(byte[]b)throws Exception{return hex(MessageDigest.getInstance("SHA-256").digest(b));}
    private void need(boolean ok,String s){if(!ok)throw new IllegalStateException(s);}
    private Address at(long v){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v&0xffffffffL);}
    private void json(String name,Object value)throws Exception{Files.writeString(output.resolve(name),pretty.toJson(value)+"\n",StandardOpenOption.CREATE_NEW);}
    private int offset(long va,int n){for(long[]l:loads)if(va>=l[0]&&va-l[0]+n<=l[2])return(int)(l[1]+va-l[0]);throw new IllegalStateException("Not original file backed "+h32(va));}
    private byte[]source(long va,int n)throws Exception{byte[]b=Arrays.copyOfRange(elf,offset(va,n),offset(va,n)+n),p=new byte[n];need(currentProgram.getMemory().getBytes(at(va),p)==n&&Arrays.equals(b,p),"Source mismatch "+h32(va));return b;}
    private List<Object>functions()throws Exception{
        List<Object>r=new ArrayList<>();for(long entry:ENTRIES){Function f=currentProgram.getFunctionManager().getFunctionAt(at(entry));need(f!=null,"Missing function "+h32(entry));allowed.add(f.getBody());List<Object>ranges=new ArrayList<>();for(AddressRange span:f.getBody().getAddressRanges()){long va=span.getMinAddress().getOffset();int n=Math.toIntExact(span.getLength());byte[]b=source(va,n);ranges.add(obj("address",h32(va),"length",n,"file_offset",offset(va,n),"hex",hex(b),"sha256",sha(b)));}r.add(obj("function_address",h32(entry),"source_ranges",ranges));}return r;
    }
    private static void put32(byte[]b,int off,long v){ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(off,(int)v);}
    private static void text(byte[]b,int off,byte[]s){System.arraycopy(s,0,b,off,s.length);b[off+s.length]=0;}
    private static class Case{long entry,a0,a1,a2,a3;int alignment,length,variant,selector;String category;Map<String,byte[]>bytes=new LinkedHashMap<>();}
    private final Map<String,Long>bases=new LinkedHashMap<>();
    private Case make(long entry,int alignment,int length,int variant,int selector,Random rng){
        Case c=new Case();c.entry=entry;c.alignment=alignment;c.length=length;c.variant=variant;c.selector=selector;
        for(String name:bases.keySet()){byte[]b=new byte[name.equals("self")?0x200:name.equals("block")?0x480:0x400];rng.nextBytes(b);c.bytes.put(name,b);}
        byte[]s=new byte[length];for(int i=0;i<length;i++)s[i]=(byte)(1+rng.nextInt(255));text(c.bytes.get("source"),alignment,s);text(c.bytes.get("destination"),alignment,s);
        c.a0=DATA+alignment;c.a1=OUT+alignment;
        if(entry==0x1fda0c){c.category="aligned-strcmp-original-mmi";c.bytes.put("destination",c.bytes.get("source").clone());if(variant>0&&length>0){int pos=variant==1?0:variant==2?length/2:length-1;c.bytes.get("destination")[alignment+pos]^=(byte)0x80;}}
        else if(entry==0x1fdb50){c.category="aligned-strcpy-original-mmi";c.a0=OUT+alignment;c.a1=DATA+alignment;Arrays.fill(c.bytes.get("destination"),(byte)0xA5);}
        else if(entry==0x1fdc64){c.category="aligned-strlen-original-mmi";c.a1=0;}
        else if(entry==0x10d680){c.category="reader-original-aligned-strlen";c.a0=SELF;c.a1=0;put32(c.bytes.get("self"),8,BLOCK);put32(c.bytes.get("self"),0xd0,0);put32(c.bytes.get("self"),0xd8,DATA+alignment);put32(c.bytes.get("block"),0x430,DATA);}
        else{c.category="template-original-aligned-repeated-strlen";c.a0=SELF;c.a1=selector;c.a2=DATA+alignment;put32(c.bytes.get("self"),0xb0+selector*4,BLOCK);}
        return c;
    }
    private List<Case>cases(){
        Random rng=new Random(SEED);List<Case>r=new ArrayList<>();int[]lengths={0,1,7,8,15,16,17,31,32,63,127};
        for(long entry:new long[]{0x1fdb50,0x1fdc64})for(int alignment:new int[]{0,16,32})for(int n:lengths)r.add(make(entry,alignment,n,0,0,rng));
        for(int alignment:new int[]{0,16})for(int n:lengths)for(int variant=0;variant<4;variant++)r.add(make(0x1fda0c,alignment,n,variant,0,rng));
        for(long entry:new long[]{0x10d4c8,0x10d590})for(int alignment:new int[]{0,16})for(int n:new int[]{0,1,7,12,13,15})for(int selector:new int[]{0,2,4})r.add(make(entry,alignment,n,0,selector,rng));
        for(int alignment:new int[]{0,16})for(int n:lengths)r.add(make(0x10d680,alignment,n,0,0,rng));
        return r;
    }
    private Map<String,Object>regs(EmulatorHelper e){Map<String,Object>r=new LinkedHashMap<>();for(String n:REGS)r.put(n,h(e.readRegister(n).longValue()));r.put("pc",h32(e.getExecutionAddress().getOffset()));return r;}
    private List<Object>memory(EmulatorHelper e,Case c){List<Object>r=new ArrayList<>();for(String name:bases.keySet())r.add(obj("name",name,"address",h32(bases.get(name)),"hex",hex(e.readMemory(at(bases.get(name)),c.bytes.get(name).length))));return r;}
    private Map<String,Object>emulate(Case c,int id)throws Exception{
        EmulatorHelper e=new EmulatorHelper(currentProgram);KamaitachiMmiUserops mmi=new KamaitachiMmiUserops(e);List<Object>faults=new ArrayList<>(),trace=new ArrayList<>();
        Map<String,Object>r=obj("id",String.format("mmi-libc-%03d",id),"function_address",h32(c.entry),"category",c.category,"return_defined",true,"parameters",obj("alignment",c.alignment,"length",c.length,"variant",c.variant,"selector",c.selector));
        try{
            e.setMemoryFaultHandler(new MemoryFaultHandler(){public boolean unknownAddress(Address a,boolean w){faults.add(obj("address",a.toString(),"write",w));return false;}public boolean uninitializedRead(Address a,int n,byte[]b,int o){faults.add(obj("address",a.toString(),"size",n));return false;}});
            for(String n:REGS)e.writeRegister(n+"_qw",BigInteger.ZERO);e.writeRegister("pc_qw",BigInteger.ZERO);
            e.writeRegister("a0",c.a0);e.writeRegister("a1",c.a1);e.writeRegister("a2",c.a2);e.writeRegister("a3",c.a3);e.writeRegister("gp",0x23daf0);e.writeRegister("sp",SP);e.writeRegister("ra",RETURN);e.writeRegister(e.getPCRegister(),c.entry);
            for(String n:bases.keySet())e.writeMemory(at(bases.get(n)),c.bytes.get(n));
            r.put("input",obj("registers",regs(e),"memory",memory(e,c)));e.enableMemoryWriteTracking(true);String status="step_limit";int steps=0;
            for(;steps<20000;steps++){
                monitor.checkCancelled();Address pc=e.getExecutionAddress();if(pc.equals(at(RETURN))){status="returned";break;}if(!allowed.contains(pc)){status="escaped_original_functions";break;}
                Instruction ins=currentProgram.getListing().getInstructionAt(pc);need(ins!=null,"Undefined original instruction");byte[]raw=source(pc.getOffset(),ins.getLength());need(Arrays.equals(raw,e.readMemory(pc,raw.length)),"Emulator changed code");
                boolean ok=e.step(monitor);trace.add(obj("pc_before",h32(pc.getOffset()),"file_offset",offset(pc.getOffset(),raw.length),"hex",hex(raw),"disassembly",ins.toString(),"pc_after",h32(e.getExecutionAddress().getOffset()),"step_ok",ok));if(!ok){status="emulation_error";steps++;break;}
            }
            if(e.getExecutionAddress().equals(at(RETURN)))status="returned";if(!faults.isEmpty())status="memory_fault";
            List<Object>writes=new ArrayList<>();for(AddressRange range:e.getTrackedMemoryWriteSet().getAddressRanges()){
                long lo=range.getMinAddress().getOffset(),hi=range.getMaxAddress().getOffset();boolean captured=false;for(String n:bases.keySet())if(lo>=bases.get(n)&&hi<bases.get(n)+c.bytes.get(n).length){captured=true;break;}
                if(range.getMinAddress().getAddressSpace().getName().equals("ram")&&!captured)status="uncaptured_write";writes.add(obj("start",range.getMinAddress().toString(true),"end_inclusive",range.getMaxAddress().toString(true),"length",range.getLength()));
            }
            r.put("status",status);r.put("steps",steps);r.put("output",obj("registers",regs(e),"memory",memory(e,c)));r.put("trace",trace);r.put("tracked_writes",writes);r.put("faults",faults);r.put("emulator_error",e.getLastError());r.put("mmi_userop_counts",mmi.counts);
        }finally{e.dispose();}
        return r;
    }
    @Override public void run()throws Exception{
        String[]args=getScriptArgs();need(args.length==3,"Usage: <new-output-dir> <original-ELF> <extension-dir>");need(LANG.equals(currentProgram.getLanguageID().toString()),"Language mismatch");
        elf=Files.readAllBytes(Path.of(args[1]));need(SHA.equals(sha(elf))&&SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()),"ELF mismatch");
        ByteBuffer b=ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);int ph=b.getInt(28),count=Short.toUnsignedInt(b.getShort(44));for(int i=0;i<count;i++){int p=ph+32*i;if(b.getInt(p)==1)loads.add(new long[]{Integer.toUnsignedLong(b.getInt(p+8)),Integer.toUnsignedLong(b.getInt(p+4)),Integer.toUnsignedLong(b.getInt(p+16))});}
        output=Path.of(args[0]).toAbsolutePath().normalize();Path allowedOutput=Path.of(args[1]).toAbsolutePath().normalize().getParent().getParent().getParent().resolve("analysis/ghidra");need(output.startsWith(allowedOutput)&&!Files.exists(output),"Output must be new workspace evidence dir");Files.createDirectory(output);
        bases.put("self",SELF);bases.put("source",DATA);bases.put("block",BLOCK);bases.put("destination",OUT);bases.put("stack",STACK);
        byte[]harness;try(InputStream stream=getSourceFile().getInputStream()){harness=stream.readAllBytes();}byte[]helper=Files.readAllBytes(Path.of("tools/ghidra/KamaitachiMmiUserops.java"));Files.write(output.resolve("EmulateKamaitachiMmiLibc.java"),harness);Files.write(output.resolve("KamaitachiMmiUserops.java"),helper);
        List<Object>language=new ArrayList<>();for(String n:new String[]{"extension.properties","data/languages/r5900.sla","data/languages/eecore.sinc","data/languages/base.sinc","data/languages/mips.sinc","data/languages/r5900.cspec"})language.add(obj("path",n,"sha256",sha(Files.readAllBytes(Path.of(args[2]).resolve(n)))));
        Map<String,Object>manifest=obj("schema",1,"format","kamaitachi-original-instruction-oracle","status","in_progress","started_utc",Instant.now().toString(),"elf_sha256",SHA,"language_id",LANG,"ghidra_version",Application.getApplicationVersion(),"harness_sha256",sha(harness),"mmi_helper_sha256",sha(helper),"extension_files",language,"engine","Ghidra EmulatorHelper + isolated KamaitachiMmiUserops; not stock Ghidra or hardware/PCSX2 execution","mmi_operations",KamaitachiMmiUserops.NAMES,"engine_validation","analysis/ghidra/mmi-validation-v1/audit.json","expected_value_source","Only emulator output; no host libc or game-function stubs","cases_file","cases.jsonl","seed",h(SEED),"program_mutations",List.of(),"limits",List.of("Synthetic explicit initialized windows; no whole-RAM snapshot","Unknown/uninitialized reads and writes outside recorded regions fail","Only six declared MMI userops enhanced; other unsupported instructions still fail","Step traces include branch delay slots within the preceding step","Raw register returns recorded, including final SLTU=0 for template entries; caller use is not implied"));
        int done=0,returned=0;List<Object>failed=new ArrayList<>();json("started.json",manifest);
        try{
            manifest.put("functions",functions());List<Case>cases=cases();manifest.put("planned_cases",cases.size());
            try(Writer w=Files.newBufferedWriter(output.resolve("cases.jsonl"),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)){for(Case c:cases){Map<String,Object>r=emulate(c,done++);compact.toJson(r,w);w.write('\n');w.flush();if("returned".equals(r.get("status")))returned++;else{failed.add(obj("id",r.get("id"),"status",r.get("status"),"error",r.get("emulator_error")));break;}}}
            manifest.put("status",done==cases.size()&&failed.isEmpty()?"oracle_completed":"oracle_failed");
        }catch(Throwable t){manifest.put("status","oracle_failed");manifest.put("error",t.toString());throw t;}
        finally{manifest.put("case_count",done);manifest.put("returned_count",returned);manifest.put("failed",failed);manifest.put("finished_utc",Instant.now().toString());if(Files.exists(output.resolve("cases.jsonl")))manifest.put("cases_sha256",sha(Files.readAllBytes(output.resolve("cases.jsonl"))));json("manifest.json",manifest);}
    }
}
