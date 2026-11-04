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
public class EmulateKamaitachiReaders extends GhidraScript {
    private static final String SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final String LANG="r5900:LE:32:default";
    private static final long SELF=0x01f00000L, DATA=0x01f02000L, BLOCK=0x01f04000L;
    private static final long STACK=0x01f0ee00L, SP=0x01f0f000L, RETURN=0x01fffff0L;
    private static final long SEED=0x4b414d4149544143L;
    private static final int STEP_LIMIT=1024;
    private static final long[] ENTRIES={0x10d5d8,0x10d610,0x10d638,0x10d680,0x10d6c8,0x10d700,0x10d720,0x10d728,0x10d738,0x10d740,0x10d748,0x10d780,0x10d788,0x10d7b0,0x10d7d0,0x10d800,0x10d830,0x1fdc64};
    private static final Set<Long> RETURNS=Set.of(0x10d5d8L,0x10d610L,0x10d638L,0x10d680L,0x10d6c8L,0x10d720L,0x10d740L,0x10d748L,0x10d788L,0x1fdc64L);
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
            functions.add(obj("function_address",h32(entry),"name",function.getName(),"return_defined",RETURNS.contains(entry),"source_ranges",ranges));
        }
        return functions;
    }
    private static void put32(byte[] target,int offset,long value) {ByteBuffer.wrap(target).order(ByteOrder.LITTLE_ENDIAN).putInt(offset,(int)value);}
    private static class Case {
        String category; long entry,a1,a2; int selector=15,label=0x1234,cursor=3; Long main=null,aux=null,base=null; byte[] prefix=new byte[0];
        Case(long entry,String category,long a1,long a2){this.entry=entry;this.category=category;this.a1=a1;this.a2=a2;}
    }
    private List<Case> cases() {
        List<Case> result=new ArrayList<>(); Random random=new Random(SEED);
        String[] patterns={"0000000000000000","ffffffffffffffff","0123456789abcdef","80007fff81fe01aa","829f82a081408160","123456789abcdef0"};
        for(long entry:new long[]{0x10d5d8,0x10d6c8}) {
            for(String pattern:patterns)for(int count=0;count<=8;count++) {Case c=new Case(entry,"reader-fixed-0-to8",count,0);c.prefix=HexFormat.of().parseHex(pattern);result.add(c);}
            for(int i=0;i<64;i++){Case c=new Case(entry,"reader-random-fixed-seed",random.nextInt(9),0);c.prefix=new byte[8];random.nextBytes(c.prefix);c.cursor=random.nextInt(8);result.add(c);}
        }
        long[] arguments={-257,-1,0,1,3,127,256,0x7fffffffL,0x80000000L,0xffffffffL};
        for(long entry:new long[]{0x10d610,0x10d788,0x10d700,0x10d7b0})for(int selector:new int[]{0,15,49})for(long argument:arguments) {
            Case c=new Case(entry,"cursor-arithmetic",argument,0);c.selector=selector;result.add(c);
        }
        for(long entry:new long[]{0x10d610,0x10d788})for(long cursor:new long[]{0x7ffffffcL,0xfffffffcL})for(long argument:new long[]{-8,0,8}) {
            Case c=new Case(entry,"cursor-wrap-register-only",argument,0);c.main=cursor;c.aux=cursor;result.add(c);
        }
        for(long entry:new long[]{0x10d700,0x10d7b0})for(long base:new long[]{0x7ffffffcL,0xfffffffcL}) {
            Case c=new Case(entry,"base-wrap-no-dereference",8,0);c.base=base;result.add(c);
        }
        for(long entry:new long[]{0x10d720,0x10d728,0x10d740,0x10d748})for(long value:new long[]{0,1,15,0x7fffffffL,0x80000000L,0xffffffffL}) {
            Case c=new Case(entry,"getter-and-copy-raw-state",0,0);c.selector=(int)value;c.label=(int)value;c.main=value;c.aux=0x543210L;result.add(c);
        }
        for(long entry:new long[]{0x10d738,0x10d780})for(long value:arguments)result.add(new Case(entry,"selector-label-setter",value,0));
        for(long entry:new long[]{0x10d7d0,0x10d800})for(int value:new int[]{0,1,3,7})result.add(new Case(entry,"template-selector-real-calls",value,0));
        for(int selector:new int[]{0,15,17,32,41,49})for(long offset:new long[]{-16,0,3,0x7fffffffL,0x80000000L})result.add(new Case(0x10d830,"combined-selector-relative-real-calls",selector,offset));
        for(int marker:new int[]{0,1,127,255})for(int cursor=0;cursor<4;cursor++){Case c=new Case(0x10d638,"framed-header-real-calls",0,0);c.cursor=cursor;c.prefix=new byte[]{(byte)marker,0x12,0x34,0x56};result.add(c);}
        return result;
    }
    private List<Case> stringCases(boolean mmiProbe) {
        List<Case> result=new ArrayList<>();Random random=new Random(SEED);
        int[] alignments=mmiProbe?new int[]{0,16}:new int[]{1,3,7,8,9,15,17};
        for(int cursor:alignments)for(int length:new int[]{0,1,7,8,15,16,31,63}) {
            Case c=new Case(0x10d680,mmiProbe?"cstring-mmi-engine-probe":"cstring-real-scalar-or-ld-callee",0,0);c.cursor=cursor;c.prefix=new byte[length+1];
            for(int i=0;i<length;i++)c.prefix[i]=(byte)(random.nextInt(255)+1);
            c.prefix[length]=0;result.add(c);
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
        Map<String,Object> result=obj("id",String.format("reader-%04d",index),"function_address",h32(c.entry),"category",c.category,"return_defined",RETURNS.contains(c.entry),
            "oracle_authority","Ghidra EmulatorHelper executing original ELF SLEIGH p-code; not PCS X2 hardware observation");
        try {
            emulator.setMemoryFaultHandler(new MemoryFaultHandler() {
                public boolean unknownAddress(Address at,boolean write){faults.add(obj("type","unknown_address","address",at.toString(true),"write",write));return false;}
                public boolean uninitializedRead(Address at,int size,byte[] buffer,int offset){faults.add(obj("type","uninitialized_read","address",at.toString(true),"size",size));return false;}
            });
            for(String name:REGS)emulator.writeRegister(name+"_qw",BigInteger.ZERO);
            emulator.writeRegister("pc_qw",BigInteger.ZERO);
            emulator.writeRegister("a0",SELF);emulator.writeRegister("a1",c.a1);emulator.writeRegister("a2",c.a2);
            emulator.writeRegister("ra",RETURN);emulator.writeRegister("sp",SP);emulator.writeRegister(emulator.getPCRegister(),c.entry);
            byte[] self=new byte[0x200],data=new byte[128],block=new byte[0x440],stack=new byte[0x400];
            Random random=new Random(SEED+index);random.nextBytes(self);random.nextBytes(data);random.nextBytes(block);random.nextBytes(stack);
            for(int selector=0;selector<50;selector++)put32(self,8+selector*4,BLOCK);
            put32(self,0xd0,c.selector);put32(self,0xd4,c.label);put32(self,0xd8,c.main==null?DATA+c.cursor:c.main);put32(self,0xdc,c.aux==null?DATA+c.cursor:c.aux);
            put32(block,0x430,c.base==null?DATA:c.base);System.arraycopy(c.prefix,0,data,c.cursor,c.prefix.length);
            emulator.writeMemory(address(SELF),self);emulator.writeMemory(address(DATA),data);emulator.writeMemory(address(BLOCK),block);emulator.writeMemory(address(STACK),stack);
            Map<String,long[]> regions=new LinkedHashMap<>();regions.put("self",new long[]{SELF,self.length});regions.put("data",new long[]{DATA,data.length});regions.put("block",new long[]{BLOCK,block.length});regions.put("stack",new long[]{STACK,stack.length});
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
            for(AddressRange range:writeSet.getAddressRanges())writes.add(obj("start",range.getMinAddress().toString(true),"end_inclusive",range.getMaxAddress().toString(true),"length",range.getLength()));
            result.put("status",status);result.put("steps",steps);result.put("output",obj("registers",registers(emulator),"memory",memory(emulator,regions)));
            result.put("trace",trace);result.put("tracked_writes",writes);result.put("faults",faults);result.put("emulator_error",emulator.getLastError());
        } catch(Exception error) {result.put("status","harness_exception");result.put("error",error.toString());result.put("faults",faults);result.put("trace",trace);}
        finally {emulator.dispose();}
        return result;
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();if(args.length<3 || args.length>4)throw new IllegalArgumentException("Usage: EmulateKamaitachiReaders.java <new-output-directory> <original-ELF> <extension-directory> [readers|strings|mmi-probe]");
        String group=args.length==4?args[3]:"readers";if(!Set.of("readers","strings","mmi-probe").contains(group))throw new IllegalArgumentException("Unknown testcase group");
        if(currentProgram==null || !LANG.equals(currentProgram.getLanguageID().toString()))throw new IllegalStateException("Requires R5900 current program");
        original=Files.readAllBytes(Path.of(args[1]));if(!SHA.equals(sha(original)) || !SHA.equalsIgnoreCase(String.valueOf(currentProgram.getExecutableSHA256())))throw new IllegalStateException("ELF SHA mismatch");
        ByteBuffer elf=ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);int phoff=elf.getInt(28), count=Short.toUnsignedInt(elf.getShort(44));
        for(int i=0;i<count;i++){int pos=phoff+i*32;if(elf.getInt(pos)==1)loads.add(new long[]{Integer.toUnsignedLong(elf.getInt(pos+8)),Integer.toUnsignedLong(elf.getInt(pos+4)),Integer.toUnsignedLong(elf.getInt(pos+16))});}
        output=Path.of(args[0]).toAbsolutePath().normalize();if(Files.exists(output,LinkOption.NOFOLLOW_LINKS))throw new IOException("Refuse existing oracle output");Files.createDirectories(output.getParent());Files.createDirectory(output);
        List<Object> languageFiles=new ArrayList<>();Path extension=Path.of(args[2]);
        for(String name:new String[]{"extension.properties","data/languages/r5900.sla","data/languages/base.sinc","data/languages/mips.sinc","data/languages/r5900.cspec"}){byte[] content=Files.readAllBytes(extension.resolve(name));languageFiles.add(obj("path",name,"sha256",sha(content),"size",content.length));}
        byte[] harness;try(InputStream stream=getSourceFile().getInputStream()){harness=stream.readAllBytes();}Files.write(output.resolve("EmulateKamaitachiReaders.java"),harness,StandardOpenOption.CREATE_NEW);
        Map<String,Object> manifest=obj("schema",1,"format","kamaitachi-original-instruction-oracle","status","in_progress","started_utc",Instant.now().toString(),"elf_sha256",SHA,"language_id",LANG,"ghidra_version",Application.getApplicationVersion(),"case_group",group,"harness_sha256",sha(harness),
            "engine","ghidra.app.emulator.EmulatorHelper/currentProgram; SLEIGH p-code","extension_files",languageFiles,"seed",h(SEED),"generator","java.util.Random","cases_file","cases.jsonl","expected_value_source","Only emulator output; no C/C++/Python reference reader formula used",
            "register_defaults","All32 general128-bit _qw registers zeroed before explicita0/a1/a2/sp/ra/pc assignment; low64 values recorded; void v0 is not a semantic result",
            "guest_layout",obj("self",h32(SELF),"data",h32(DATA),"block",h32(BLOCK),"stack",h32(STACK),"sp",h32(SP),"return_sentinel",h32(RETURN)),"step_limit",STEP_LIMIT,
            "limits",List.of("Ghidra/SLEIGH oracle, not PCSX2 or original console observation","SLEIGH implementation bugs remain possible; source/language hashes retained","PC samples are EmulatorHelper instruction steps; branch p-code may include delay-slot execution","Synthetic guest objects initialized explicitly, not original game cold heap","No history or strlen dependencies stubbed; only the declared original-function closure is executed","All unknown/uninitialized reads fail rather than silently initialize zero","strings group excludes16-byte-aligned MMI path; mmi-probe group separately records actual engine capability"));
        int returned=0,total=0;List<Object> failed=new ArrayList<>();
        json("started.json",manifest);
        try {
            manifest.put("functions",describeFunctions());List<Case> cases=group.equals("readers")?cases():stringCases(group.equals("mmi-probe"));manifest.put("planned_cases",cases.size());
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
