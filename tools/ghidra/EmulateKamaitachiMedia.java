// Execute original ScriptData instructions with Ghidra/SLEIGH, never a C model.
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
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;

@SuppressWarnings("removal")
public class EmulateKamaitachiMedia extends GhidraScript {
    private static final String SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final String LANG="r5900:LE:32:default";
    private static final long SELF=0x01f00000L, DATA=0x01f02000L, BLOCK=0x01f04000L;
    private static final long RECORDS=0x01e00000L, LABELS=0x01d00000L, LABEL=0x01f06000L, OUT=0x01f08000L, SNAPSHOTS=0x01c00000L;
    private static final long STACK=0x01f0ee00L, SP=0x01f0f000L, RETURN=0x01fffff0L;
    private static final long SEED=0x4b414d4149544143L;
    private static final int STEP_LIMIT=4096;
    private static final long SCRIPT=0x01f01000L, GP=0x0023daf0L, GLOBALS=0x00235e00L, PROVIDER=0x01f07000L, REGISTRY=0x01d00000L, LINK=0x01d01000L, BUCKET=0x01d02000L, DESCRIPTOR=0x01d04000L, LOADER=0x00206250L;
    private static final long[] ENTRIES={0x101a70,0x101aa8,0x101b10,0x101b58,0x11dac0,0x11dc40,0x11e310,0x127520,0x137318,0x137350,0x1373b8,0x137568,0x137578,0x137598,0x10fb38,0x1133a8,0x10d638,0x10d680,0x10d5d8,0x10d610,0x10d700,0x10d720,0x1fdc64,0x1fdb50,0x1fda0c,0x1375d8};
    private static final Set<Long> VOIDS=Set.of(0x10d700L,0x137578L,0x137598L,0x1375d8L);
    private static final String[] REGS={"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","s8","ra"};
    private final Gson pretty=new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create();
    private final Gson compact=new GsonBuilder().serializeNulls().disableHtmlEscaping().create();
    private final AddressSet allowedCode=new AddressSet();
    private byte[] original;
    private final List<long[]> loads=new ArrayList<>();
    private Path output;

    private static Map<String,Object> obj(Object... args) { Map<String,Object> r=new LinkedHashMap<>(); for(int i=0;i<args.length;i+=2)r.put((String)args[i],args[i+1]);return r; }
    private static String h(long value) { return String.format("0x%016x",value); }
    private static String h32(long value) { return String.format("0x%08x",value&0xffffffffL); }
    private static String hex(byte[] bytes) { return HexFormat.of().formatHex(bytes); }
    private static String sha(byte[] bytes) throws Exception {return hex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private Address address(long value) { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value&0xffffffffL); }
    private void json(String name,Object value) throws Exception {
        try(Writer w=Files.newBufferedWriter(output.resolve(name),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)){pretty.toJson(value,w);w.write('\n');}
    }
    private int fileOffset(long va,int size) {
        for(long[] load:loads) if(va>=load[0] && va-load[0]+size<=load[2])return (int)(load[1]+va-load[0]);
        throw new IllegalArgumentException("Execution range outside original ELF: "+h32(va));
    }
    private byte[] sourceBytes(long va,int size) throws Exception {
        int off=fileOffset(va,size); byte[] expected=Arrays.copyOfRange(original,off,off+size), actual=new byte[size];
        if(currentProgram.getMemory().getBytes(address(va),actual)!=size || !Arrays.equals(expected,actual))throw new IllegalStateException("Program bytes differ from source at "+h32(va));
        return actual;
    }
    private List<Object> describeFunctions() throws Exception {
        List<Object> functions=new ArrayList<>();
        for(long entry:ENTRIES) {
            Function function=currentProgram.getFunctionManager().getFunctionAt(address(entry));
            if(function==null)throw new IllegalStateException("Missing existing function "+h32(entry));
            List<Object> ranges=new ArrayList<>();
            for(AddressRange range:function.getBody().getAddressRanges()) {
                int size=Math.toIntExact(range.getLength()); long va=range.getMinAddress().getOffset(); byte[] raw=sourceBytes(va,size);
                ranges.add(obj("address",h32(va),"length",size,"file_offset",fileOffset(va,size),"hex",hex(raw),"sha256",sha(raw)));
            }
            allowedCode.add(function.getBody());
            functions.add(obj("function_address",h32(entry),"name",function.getName(),"return_defined",!VOIDS.contains(entry),"source_ranges",ranges));
        }
        return functions;
    }
    private static void put32(byte[] target,int offset,long value) {ByteBuffer.wrap(target).order(ByteOrder.LITTLE_ENDIAN).putInt(offset,(int)value);}
    private static void put16(byte[] target,int offset,int value) {ByteBuffer.wrap(target).order(ByteOrder.LITTLE_ENDIAN).putShort(offset,(short)value);}
    private static void string(byte[] target,int offset,byte[] value) {System.arraycopy(value,0,target,offset,value.length);target[offset+value.length]=0;}
    private static byte[] ascii(String value) {return value.getBytes(StandardCharsets.US_ASCII);}
    private static class Region {long base;byte[] bytes;Region(long base,byte[] bytes){this.base=base;this.bytes=bytes;}}
    private static class Case {
        String category;long entry,a0=SELF,a1,a2,a3;final Map<String,Region> regions=new LinkedHashMap<>();
        Case(long entry,String category,long a1,long a2,long a3){this.entry=entry;this.category=category;this.a1=a1;this.a2=a2;this.a3=a3;}
        byte[] add(String name,long base,int size,Random random){byte[] bytes=new byte[size];random.nextBytes(bytes);regions.put(name,new Region(base,bytes));return bytes;}
        byte[] get(String name){return regions.get(name).bytes;}
    }
    private Case base(long entry,String category,long a1,long a2,long a3,Random random) throws Exception {
        Case c=new Case(entry,category,a1,a2,a3);
        byte[] manager=c.add("self",SELF,0x900,random),script=c.add("script",SCRIPT,0x200,random),data=c.add("data",DATA,0x400,random);
        byte[] block=c.add("script_block",BLOCK,0x440,random),provider=c.add("provider",PROVIDER,0x20,random),globals=c.add("globals",GLOBALS,0x400,random);
        c.add("outputs",OUT,0x40,random);c.add("stack",STACK,0x400,random);
        byte[] registry=c.add("registry",REGISTRY,0x90,random),link=c.add("link",LINK,0x420,random),bucket=c.add("bucket",BUCKET,0x100,random),descriptor=c.add("descriptor",DESCRIPTOR,0x100,random);
        byte[] loader=c.add("loader",LOADER,0xec0,random);
        put32(manager,0x38,SCRIPT);put32(globals,(int)(GP-0x7cb0-GLOBALS),SELF);put32(globals,(int)(GP-0x7bf4-GLOBALS),PROVIDER);put32(globals,(int)(GP-0x7a2c-GLOBALS),1);
        for(int i=0;i<50;i++)put32(script,8+i*4,BLOCK);put32(script,0xd0,1);put32(script,0xd8,DATA+0x11);put32(block,0x430,DATA);
        put32(provider,4,REGISTRY);put32(provider,8,0);put32(provider,12,0x12345678);put32(provider,16,0xabcdef);
        put32(registry,4,LINK);put32(registry,0x84,1);for(int i=0;i<256;i++)put32(link,0x20+i*4,BUCKET);
        // Every hash bucket shares one valid scene chain; no model computes the
        // expected hash or lookup output. Scene records use source span layout.
        put16(bucket,0,2);put16(bucket,2,0x3e);put32(bucket,4,77);put32(bucket,8,DESCRIPTOR+0x40);string(bucket,12,ascii("other"));
        put16(bucket,0x42,0x3e);put32(bucket,0x44,0x80000009L);put32(bucket,0x48,DESCRIPTOR);string(bucket,0x4c,ascii("scene-x"));
        string(data,3,ascii("scene-x"));data[0x10]=0x72;data[0x11]=8;string(data,0x12,ascii("scene-x"));
        put16(descriptor,0,0);put32(loader,0,0);put32(loader,0x5bc,0);put32(loader,0xea0,3);put32(loader,0xea4,3);
        return c;
    }
    private List<Case> cases(String group) throws Exception {
        List<Case> result=new ArrayList<>();Random random=new Random(SEED);
        if(group.equals("active-boundary") || group.equals("cold-provider")) {
            Case c=base(group.equals("active-boundary")?0x127520:0x11dac0,group+"-actual-source-stop",0x10,0,0,random);
            if(group.equals("active-boundary"))put32(c.get("globals"),(int)(GP-0x7a2c-GLOBALS),0);
            else put32(c.get("globals"),(int)(GP-0x7bf4-GLOBALS),0);
            result.add(c);return result;
        }
        if(!group.equals("media"))throw new IllegalArgumentException("Unknown group "+group);
        for(long entry:new long[]{0x101a70,0x101aa8})for(int alignment:new int[]{0,1,3,8})for(long word:new long[]{0,1,0x7fff,0x8000,0xffff,0x7fffffffL,0x80000000L,0xffffffffL}) {
            Case c=base(entry,"unaligned-source-little-endian-reader",0,0,0,random);c.a0=DATA+alignment;put32(c.get("data"),alignment,word);result.add(c);
        }
        for(int length:new int[]{0,1,7,31,255})for(int pattern=0;pattern<3;pattern++) {
            Case c=base(0x101b10,"resource-name-hash-bytes",0,0,0,random);c.a0=DATA+1;byte[] name=new byte[length];for(int i=0;i<length;i++)name[i]=(byte)(pattern==0?'a':pattern==1?255:random.nextInt(255)+1);string(c.get("data"),1,name);result.add(c);
        }
        for(int mode=0;mode<5;mode++)for(int alias=0;alias<6;alias++) {
            long[][] out={{OUT,OUT+4},{0,0},{OUT,0},{0,OUT},{OUT,OUT},{REGISTRY+0x84,PROVIDER+12}};
            Case c=base(0x101b58,"resource-registry-match-count-and-output-alias-"+mode, out[alias][0],out[alias][1],DATA+3,random);c.a0=REGISTRY;
            if(mode==1)string(c.get("data"),3,ascii("absent"));
            if(mode==2)Arrays.fill(c.get("link"),0x20,0x420,(byte)0);
            if(mode==3)put32(c.get("registry"),0x84,0xffffffffL);
            if(mode==4)put16(c.get("bucket"),0,0xffff);
            result.add(c);
        }
        for(long entry:new long[]{0x137318,0x137350,0x137568})for(int state:new int[]{-1,0,1,7,8,9})for(int pending:new int[]{0,1})for(int mismatch:new int[]{0,1}) {
            Case c=base(entry,"loader-readiness-state-and-queue",0,0,0,random);put32(c.get("loader"),0,state);put32(c.get("loader"),0x5bc,pending);put32(c.get("loader"),0xea4,3+mismatch);result.add(c);
        }
        for(long value:new long[]{0,1,0x80000000L,0xffffffffL}) {
            Case c=base(0x1373b8,"active-inhibitor-predicate",0,0,0,random);put32(c.get("globals"),(int)(GP-0x7a2c-GLOBALS),value);result.add(c);
            if(value!=0){Case p=base(0x11dac0,"provider-hot-pointer",0,0,0,random);put32(p.get("globals"),(int)(GP-0x7bf4-GLOBALS),value);result.add(p);}
        }
        for(long entry:new long[]{0x137578,0x137598})for(int active:new int[]{0,1})for(int state:new int[]{0,8})for(int same:new int[]{0,1}) {
            Case c=base(entry,"request-real-queue-or-inhibitor-return",DATA+3,active,0,random);c.a0=DESCRIPTOR;put32(c.get("loader"),0,state);put32(c.get("loader"),0x5bc,same==0?0:DESCRIPTOR);result.add(c);
        }
        for(long mode:new long[]{-1,0,1,2,3,0x100000001L})for(int found:new int[]{0,1})for(int same:new int[]{0,1}) {
            Case c=base(0x11e310,"provider-begin-registry-then-request",DATA+3,mode,0,random);c.a0=PROVIDER;
            if(found==0)string(c.get("data"),3,ascii("absent"));if(same==1)put32(c.get("loader"),0x5bc,found==1?DESCRIPTOR:0);result.add(c);
        }
        for(int blocked=0;blocked<4;blocked++) {
            Case c=base(0x11dc40,"provider-72-ready-vs-wait",DATA+3,0,0,random);c.a0=PROVIDER;
            if(blocked==1)put32(c.get("loader"),0,1);if(blocked==2)put32(c.get("loader"),0x5bc,1);if(blocked==3)put32(c.get("loader"),0xea4,4);result.add(c);
        }
        for(int header:new int[]{0,1,8,255})for(int blocked=0;blocked<4;blocked++)for(int state:new int[]{0,8}) {
            Case c=base(0x127520,"opcode72-parser-and-source-rewind",0x10,0,0,random);put32(c.get("loader"),0,state);
            c.get("data")[0x11]=(byte)header;int at=header==0?0x14:0x12;if(header==0){c.get("data")[0x12]=0;c.get("data")[0x13]=1;}string(c.get("data"),at,ascii("scene-x"));
            if(blocked==1)put32(c.get("loader"),0,1);if(blocked==2){put32(c.get("loader"),0,0);put32(c.get("loader"),0x5bc,1);}if(blocked==3)put32(c.get("loader"),0xea4,4);result.add(c);
        }
        return result;
    }
    private Map<String,Object> registers(EmulatorHelper emulator) {
        Map<String,Object> result=new LinkedHashMap<>(); BigInteger mask=BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        for(String name:REGS)result.put(name,h(emulator.readRegister(name).and(mask).longValue()));
        result.put("pc",h32(emulator.getExecutionAddress().getOffset())); return result;
    }
    private List<Object> memory(EmulatorHelper emulator,Map<String,long[]> regions) {
        List<Object> result=new ArrayList<>();
        for(Map.Entry<String,long[]> region:regions.entrySet()) {
            byte[] bytes=emulator.readMemory(address(region.getValue()[0]),(int)region.getValue()[1]);
            if(bytes==null || bytes.length!=region.getValue()[1])throw new IllegalStateException("Short guest snapshot read");
            result.add(obj("name",region.getKey(),"address",h32(region.getValue()[0]),"hex",hex(bytes)));
        }
        return result;
    }
    private Map<String,Object> emulate(Case c,int index) throws Exception {
        List<Object> faults=new ArrayList<>(),trace=new ArrayList<>(); EmulatorHelper emulator=new EmulatorHelper(currentProgram);
        Map<String,Object> result=obj("id",String.format("media-%04d",index),"function_address",h32(c.entry),"category",c.category,"return_defined",!VOIDS.contains(c.entry),
            "oracle_authority","Ghidra EmulatorHelper executing original ELF SLEIGH p-code; not PCS X2 hardware observation");
        try {
            emulator.setMemoryFaultHandler(new MemoryFaultHandler() {
                public boolean unknownAddress(Address at,boolean write){faults.add(obj("type","unknown_address","address",at.toString(true),"write",write));return false;}
                public boolean uninitializedRead(Address at,int size,byte[] buffer,int offset){faults.add(obj("type","uninitialized_read","address",at.toString(true),"size",size));return false;}
            });
            for(String name:REGS)emulator.writeRegister(name+"_qw",BigInteger.ZERO);
            emulator.writeRegister("pc_qw",BigInteger.ZERO);
            emulator.writeRegister("gp",GP);
            emulator.writeRegister("a0",c.a0);emulator.writeRegister("a1",c.a1);emulator.writeRegister("a2",c.a2);emulator.writeRegister("a3",c.a3);
            emulator.writeRegister("ra",RETURN);emulator.writeRegister("sp",SP);emulator.writeRegister(emulator.getPCRegister(),c.entry);
            Map<String,long[]> regions=new LinkedHashMap<>();
            for(Map.Entry<String,Region> item:c.regions.entrySet()) {
                Region r=item.getValue();regions.put(item.getKey(),new long[]{r.base,r.bytes.length});emulator.writeMemory(address(r.base),r.bytes);
            }
            result.put("fixture",obj("snapshot_scope","Only explicitly initialized object/record/string/copy windows and ABI stack; no whole-RAM dump","request_policy","Accepted72 fixtures explicitly exercise original nonzero inhibitor early return, not active media preparation or a stub","expected_values","No semantic model; original instruction execution only"));
            result.put("input",obj("registers",registers(emulator),"memory",memory(emulator,regions)));
            emulator.enableMemoryWriteTracking(true);String status="step_limit";int steps=0;
            for(;steps<STEP_LIMIT;steps++) {
                monitor.checkCancelled();Address pc=emulator.getExecutionAddress();
                if(pc.equals(address(RETURN))){status="returned";break;}
                if(!allowedCode.contains(pc)){status="escaped_known_original_functions";break;}
                Instruction instruction=currentProgram.getListing().getInstructionAt(pc);
                if(instruction==null){status="undefined_original_instruction";break;}
                byte[] raw=sourceBytes(pc.getOffset(),instruction.getLength());
                boolean stepped=emulator.step(monitor);
                trace.add(obj("pc_before",h32(pc.getOffset()),"file_offset",fileOffset(pc.getOffset(),raw.length),"hex",hex(raw),"disassembly",instruction.toString(),
                    "pc_after",h32(emulator.getExecutionAddress().getOffset()),"step_ok",stepped,"v0_after",h(emulator.readRegister("v0").longValue())));
                if(!stepped){status="emulation_error";steps++;break;}
            }
            if(emulator.getExecutionAddress().equals(address(RETURN)))status="returned";
            if(!faults.isEmpty())status="memory_fault";
            List<Object> writes=new ArrayList<>();AddressSetView writeSet=emulator.getTrackedMemoryWriteSet();
            for(AddressRange range:writeSet.getAddressRanges()) {
                writes.add(obj("start",range.getMinAddress().toString(true),"end_inclusive",range.getMaxAddress().toString(true),"length",range.getLength()));
                if(range.getMinAddress().getAddressSpace().getName().equals("ram")) {
                    long start=range.getMinAddress().getOffset(),end=range.getMaxAddress().getOffset();boolean captured=false;
                    for(long[] region:regions.values())if(start>=region[0] && end<region[0]+region[1]){captured=true;break;}
                    if(!captured){status="write_outside_initialized_guest_windows";faults.add(obj("type","uncaptured_guest_write","start",h32(start),"end",h32(end)));}
                }
            }
            result.put("status",status);result.put("steps",steps);result.put("output",obj("registers",registers(emulator),"memory",memory(emulator,regions)));
            result.put("trace",trace);result.put("tracked_writes",writes);result.put("faults",faults);result.put("emulator_error",emulator.getLastError());
        } catch(Exception error) {result.put("status","harness_exception");result.put("error",error.toString());result.put("faults",faults);result.put("trace",trace);}
        finally {emulator.dispose();}
        return result;
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();if(args.length<3 || args.length>4)throw new IllegalArgumentException("Usage: EmulateKamaitachiMedia.java <new-output-directory> <original-ELF> <extension-directory> [media|active-boundary|cold-provider]");
        String group=args.length==4?args[3]:"media";
        if(currentProgram==null || !LANG.equals(currentProgram.getLanguageID().toString()))throw new IllegalStateException("Requires R5900 current program");
        original=Files.readAllBytes(Path.of(args[1]));if(!SHA.equals(sha(original)) || !SHA.equalsIgnoreCase(String.valueOf(currentProgram.getExecutableSHA256())))throw new IllegalStateException("ELF SHA mismatch");
        ByteBuffer elf=ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);int phoff=elf.getInt(28), count=Short.toUnsignedInt(elf.getShort(44));
        for(int i=0;i<count;i++){int pos=phoff+i*32;if(elf.getInt(pos)==1)loads.add(new long[]{Integer.toUnsignedLong(elf.getInt(pos+8)),Integer.toUnsignedLong(elf.getInt(pos+4)),Integer.toUnsignedLong(elf.getInt(pos+16))});}
        output=Path.of(args[0]).toAbsolutePath().normalize();Path allowedOutput=Path.of(args[1]).toAbsolutePath().normalize().getParent().getParent().getParent().resolve("analysis/ghidra");if(!output.startsWith(allowedOutput))throw new IOException("Oracle output must remain inside project analysis/ghidra");if(Files.exists(output,LinkOption.NOFOLLOW_LINKS))throw new IOException("Refuse existing oracle output");Files.createDirectories(output.getParent());Files.createDirectory(output);
        List<Object> languageFiles=new ArrayList<>();Path extension=Path.of(args[2]);
        for(String name:new String[]{"extension.properties","data/languages/r5900.sla","data/languages/base.sinc","data/languages/mips.sinc","data/languages/r5900.cspec"}){byte[] content=Files.readAllBytes(extension.resolve(name));languageFiles.add(obj("path",name,"sha256",sha(content),"size",content.length));}
        byte[] harness;try(InputStream stream=getSourceFile().getInputStream()){harness=stream.readAllBytes();}Files.write(output.resolve("EmulateKamaitachiMedia.java"),harness,StandardOpenOption.CREATE_NEW);
        Map<String,Object> manifest=obj("schema",1,"format","kamaitachi-original-instruction-oracle","status","in_progress","started_utc",Instant.now().toString(),"elf_sha256",SHA,"language_id",LANG,"ghidra_version",Application.getApplicationVersion(),"case_group",group,"harness_sha256",sha(harness),
            "engine","ghidra.app.emulator.EmulatorHelper/currentProgram; SLEIGH p-code","extension_files",languageFiles,"seed",h(SEED),"generator","java.util.Random","cases_file","cases.jsonl","expected_value_source","Only emulator output; no C/C++/Python reference reader formula used",
            "register_defaults","All32 general128-bit _qw registers zeroed before explicit a0/a1/a2/a3/sp/ra/pc assignment; low64 values recorded; void v0 is not a semantic result",
            "guest_layout",obj("self",h32(SELF),"data",h32(DATA),"block",h32(BLOCK),"stack",h32(STACK),"sp",h32(SP),"return_sentinel",h32(RETURN),"records",h32(RECORDS),"label_table",h32(LABELS),"label_record",h32(LABEL),"out",h32(OUT),"snapshot_bases",h32(SNAPSHOTS)),"step_limit",STEP_LIMIT,
            "limits",List.of("Ghidra/SLEIGH oracle, not PCSX2 or original console observation","SLEIGH implementation bugs remain possible; source/language hashes retained","PC samples are EmulatorHelper instruction steps; branch p-code may include delay-slot execution","Synthetic guest objects initialized explicitly, not original game cold heap","No dependencies stubbed; only the declared original-function closure is executed","All unknown/uninitialized reads fail rather than silently initialize zero","Synthetic explicit windows only; no whole game RAM or upstream artifact modification","Active-boundary group stops at actual1384B0 preparation call; no loader or audio method is stubbed","Cold-provider group stops at actual10FAD0 allocator dependency; runtime globals and registry are explicit synthetic fixtures"));
        int returned=0,total=0;List<Object> failed=new ArrayList<>();
        json("started.json",manifest);
        try {
            manifest.put("functions",describeFunctions());List<Case> cases=cases(group);manifest.put("planned_cases",cases.size());
            try(Writer writer=Files.newBufferedWriter(output.resolve("cases.jsonl"),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)) {
                for(Case c:cases) {
                    monitor.checkCancelled();Map<String,Object> result=emulate(c,total++);compact.toJson(result,writer);writer.write('\n');writer.flush();
                    if("returned".equals(result.get("status")))returned++;else failed.add(obj("id",result.get("id"),"entry",result.get("function_address"),"status",result.get("status"),"error",result.get("error"),"emulator_error",result.get("emulator_error")));
                    if(total%32==0)println("Oracle "+total+"/"+cases.size()+" returned="+returned);
                    // Stop on a harness/engine failure instead of generating hundreds of invalid fixtures.
                    if(!"returned".equals(result.get("status")))break;
                }
            }
            manifest.put("status",total==cases.size()&&failed.isEmpty()?"oracle_completed":"oracle_failed");
        } catch(Exception error){manifest.put("status","oracle_failed");manifest.put("error",error.toString());throw error;}
        finally {manifest.put("case_count",total);manifest.put("returned_count",returned);manifest.put("failed",failed);manifest.put("finished_utc",Instant.now().toString());if(Files.exists(output.resolve("cases.jsonl")))manifest.put("cases_sha256",sha(Files.readAllBytes(output.resolve("cases.jsonl"))));json("manifest.json",manifest);}
        println("Oracle status="+manifest.get("status")+" cases="+total+" returned="+returned);
    }
}
