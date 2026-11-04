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
public class EmulateKamaitachiTables extends GhidraScript {
    private static final String SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final String LANG="r5900:LE:32:default";
    private static final long SELF=0x01f00000L, DATA=0x01f02000L, BLOCK=0x01f04000L;
    private static final long RECORDS=0x01e00000L, LABELS=0x01d00000L, LABEL=0x01f06000L, OUT=0x01f08000L, SNAPSHOTS=0x01c00000L;
    private static final long STACK=0x01f0ee00L, SP=0x01f0f000L, RETURN=0x01fffff0L;
    private static final long SEED=0x4b414d4149544143L;
    private static final int STEP_LIMIT=50000;
    private static final long[] ENTRIES={0x10d4c8,0x10d590,0x10db48,0x10dc30,0x10ee18,0x10efc0,0x10f018,0x10f070,0x10f0c0,0x10f628,0x10f678,0x10f6e0,0x10f820,0x10f8b0,0x10f938,0x10f9b0,0x10fa48,0x10fa88,0x10d830,0x10d738,0x10d700,0x10d780,0x10e630,0x10e9d8,0x10e8d8,0x10fa68,0x10f898,0x10ef90,0x10eff0,0x1fdb50,0x1fda0c,0x1fc524,0x1fdc64};
    private static final Set<Long> VOIDS=Set.of(0x10f678L,0x10f6e0L,0x10d830L,0x10d738L,0x10d700L,0x10d780L);
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
    private Case base(long entry,String category,long a1,long a2,long a3,Random random) {
        Case c=new Case(entry,category,a1,a2,a3);
        byte[] self=c.add("self",SELF,0x200,random),data=c.add("data",DATA,0x400,random),block=c.add("block",BLOCK,0x480,random);
        byte[] block2=c.add("block2",BLOCK+0x1000,0x480,random),label=c.add("label_record",LABEL,0x400,random);
        byte[] records=c.add("records",RECORDS,0x100,random),table=c.add("label_table",LABELS,0x100,random);
        c.add("copy_buffer",OUT,0x400,random);c.add("stack",STACK,0x400,random);
        Arrays.fill(self,8,8+32*4,(byte)0);
        put32(self,8,BLOCK);put32(self,8+31*4,BLOCK+0x1000);
        for(int i=0;i<3;i++)put32(self,0xb0+i*4,BLOCK);
        put32(self,0xc4,1);put32(self,0xcc,LABELS);put32(self,0xd0,0);put32(self,0xd4,1);put32(self,0xd8,DATA+3);
        put32(self,0x134,4);put32(self,0x138,RECORDS);put32(self,0x148,0);
        put32(block,0x430,DATA);put32(block2,0x430,DATA+0x100);
        for(int bucket=0;bucket<256;bucket++){put32(block,0x30+bucket*4,LABEL);put32(block2,0x30+bucket*4,LABEL);}
        // All input buckets deliberately share the same legitimate collision
        // chain: no Java/Python/C++ hash algorithm supplies an expected value.
        for(int record=0;record<3;record++) {
            int offset=record*0x40;put16(label,offset,record==2?0:0x40);put16(label,offset+2,record);
            put32(label,offset+4,record==1?0x80000013L:0x20+record);string(label,offset+8,ascii(new String[]{"noise-a","target","noise-z"}[record]));
            put32(table,record*4,LABEL+offset);
        }
        put32(records,8,2);put32(records,12,0x01000000);string(data,1,ascii("target"));
        return c;
    }
    private List<Case> cases(String group) {
        List<Case> result=new ArrayList<>();Random random=new Random(SEED);
        if(group.equals("mmi-strcpy") || group.equals("mmi-strcmp") || group.equals("mmi-template")) {
            long entry=group.equals("mmi-strcpy")?0x1fdb50:group.equals("mmi-strcmp")?0x1fda0c:0x10d4c8;
            Case c=base(entry,group+"-actual-engine-capability",0,DATA+16,0,random);
            if(group.equals("mmi-template")){c.a1=0;c.a2=DATA+16;string(c.get("data"),16,ascii("aligned"));}
            else {c.a0=OUT;c.a1=DATA+16;string(c.get("data"),16,ascii("equal-aligned-string"));string(c.get("copy_buffer"),0,ascii("equal-aligned-string"));}
            result.add(c);return result;
        }
        if(group.equals("libc")) {
            for(long entry:new long[]{0x1fdb50,0x1fdc64})for(int alignment:new int[]{1,3,8,15})for(int length:new int[]{0,1,7,8,15,16,31,63}) {
                Case c=base(entry,"libc-string-scalar-or-ld",DATA+alignment,0,0,random);
                c.a0=entry==0x1fdb50?OUT+alignment:DATA+alignment;
                byte[] text=new byte[length];for(int i=0;i<length;i++)text[i]=(byte)(random.nextInt(255)+1);string(c.get("data"),alignment,text);result.add(c);
            }
            for(int alignment:new int[]{1,8})for(int length:new int[]{0,1,7,8,16,31})for(int mismatch:new int[]{-1,0,1,7,15}) {
                Case c=base(0x1fda0c,"strcmp-unsigned-bytes-and-terminators",DATA+alignment,0,0,random);c.a0=OUT+alignment;
                byte[] text=new byte[length];for(int i=0;i<length;i++)text[i]=(byte)(random.nextInt(255)+1);
                string(c.get("data"),alignment,text);string(c.get("copy_buffer"),alignment,text);
                if(mismatch>=0 && mismatch<length)c.get("copy_buffer")[alignment+mismatch]^=(byte)0x80;
                result.add(c);
            }
            for(int alignment:new int[]{0,1,8})for(int count:new int[]{0,1,7,8,15,16,31,32,33,40,63,64,65,127})for(int delta:new int[]{-16,0,16,0x100}) {
                Case c=base(0x1fc524,"memcpy-forward-block-overlap",OUT+0x80+alignment,count,0,random);c.a0=OUT+0x80+alignment+delta;result.add(c);
            }
            return result;
        }
        if(!group.equals("tables"))throw new IllegalArgumentException("Unknown case group "+group);
        for(long entry:new long[]{0x10d4c8,0x10d590})for(int alignment:new int[]{1,8})for(int length:new int[]{0,1,7,12,13,31,63})for(int selector:new int[]{0,2}) {
            Case c=base(entry,"name-template-real-strcpy-and-repeated-strlen",selector,DATA+alignment,0,random);
            byte[] text=new byte[length];for(int i=0;i<length;i++)text[i]=(byte)(random.nextInt(255)+1);string(c.get("data"),alignment,text);result.add(c);
        }
        for(long entry:new long[]{0x10d4c8,0x10d590})for(int length:new int[]{0,7,12}) {
            Case c=base(entry,"name-template-identical-pointer-skips-copy",0,SELF+0xe4,0,random);byte[] text=new byte[length];Arrays.fill(text,(byte)'x');string(c.get("self"),0xe4,text);result.add(c);
        }
        long[] lookupEntries={0x10db48,0x10ee18,0x10efc0,0x10f018,0x10f820,0x10f8b0,0x10f938,0x10f9b0,0x10fa48,0x10fa88};
        for(long entry:lookupEntries)for(int alignment:new int[]{1,8})for(int selector:new int[]{0,31})for(int mode=0;mode<4;mode++) {
            long name=DATA+alignment;boolean wide=entry==0x10ee18||entry==0x10f938||entry==0x10f9b0;
            Case c=base(entry,"label-chain-hit-and-history-flags-"+mode,wide?name:selector,wide?0:name,0,random);
            string(c.get("data"),alignment,ascii(mode==1?"_target":"target"));string(c.get("label_record"),0x48,ascii(mode==1?"_target":"target"));
            if(selector==31)put32(c.get("self"),8,0);
            put32(c.get("records"),8,mode==2?0x3fff:(mode==3?0x10000002L:2));put32(c.get("records"),12,mode==0?0x01000000L:0);
            result.add(c);
        }
        for(long entry:new long[]{0x10f8b0,0x10f938,0x10f9b0})for(int mode=0;mode<3;mode++) {
            boolean wide=entry!=0x10f8b0;Case c=base(entry,"label-safe-miss-"+mode,wide?DATA+1:0,wide?0:DATA+1,0,random);string(c.get("data"),1,ascii("absent"));
            if(mode==1){Arrays.fill(c.get("block"),0x30,0x430,(byte)0);Arrays.fill(c.get("block2"),0x30,0x430,(byte)0);}
            if(mode==2) {
                if(wide)Arrays.fill(c.get("self"),8,8+32*4,(byte)0);
                else Arrays.fill(c.get("block"),0x30,0x430,(byte)0);
            }
            result.add(c);
        }
        for(int length:new int[]{0,1,2,7,31,32,33,255,256,257})for(int pattern=0;pattern<3;pattern++) {
            Case c=base(0x10f628,"hash-byte-shifts-counter-wrap",DATA+1,0,0,random);byte[] text=new byte[length];
            for(int i=0;i<length;i++)text[i]=(byte)(pattern==0?'a':pattern==1?255:random.nextInt(255)+1);string(c.get("data"),1,text);result.add(c);
        }
        for(int word0:new int[]{0,0x10000000,0x80000000,0x90000000,-1})for(int word1:new int[]{0,0x01000000,-1}) {
            Case c=base(0x10dc30,"history-flag-predicate",1,0,0,random);put32(c.get("records"),8,word0);put32(c.get("records"),12,word1);result.add(c);
        }
        for(long entry:new long[]{0x10f070,0x10f0c0})for(int alignment:new int[]{0,1,8})for(int count:new int[]{0,1,3,4,5,8,16})for(int delta:new int[]{-16,0,16,0x100}) {
            Case c=base(entry,"snapshot-real-memcpy-overlap",0,0,0,random);long live=OUT+0x80+alignment,snapshot=live+delta;
            put32(c.get("self"),0x134,count);put32(c.get("self"),0x138,live);put32(c.get("self"),0x13c,snapshot);put32(c.get("self"),0x148,entry==0x10f070?0:1);result.add(c);
        }
        for(int count:new int[]{0,-1,1,2}) {
            Case c=base(0x10f678,"block-relative-pointer-relocation",0,0,0,random);put32(c.get("self"),0xc4,count);put32(c.get("self"),12,BLOCK+0x1000);
            for(String n:new String[]{"block","block2"}){byte[] bytes=c.get(n);Arrays.fill(bytes,0x30,0x430,(byte)0);put32(bytes,0x30,0x450);put32(bytes,0x30+127*4,0xfffffff0L);put32(bytes,0x30+255*4,0x7fffffffL);put32(bytes,0x430,0x450);}
            result.add(c);
        }
        for(int count:new int[]{0,-1,1,2})for(int mode=0;mode<3;mode++) {
            Case c=base(0x10f6e0,"label-enumeration-terminal-and-underscore-"+mode,0,0,0,random);put32(c.get("self"),0xc4,count);put32(c.get("self"),12,BLOCK+0x1000);
            Arrays.fill(c.get("block"),0x30,0x430,(byte)0);Arrays.fill(c.get("block2"),0x30,0x430,(byte)0);
            put32(c.get("block"),0x30+127*4,LABEL);put32(c.get("block2"),0x30+255*4,LABEL+0xc0);
            put16(c.get("label_record"),0xc0,0);string(c.get("label_record"),0xc8,ascii("last"));
            if(mode>0)string(c.get("label_record"),8,ascii("_hidden"));if(mode==2)string(c.get("label_record"),0x88,ascii("_last"));result.add(c);
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
        Map<String,Object> result=obj("id",String.format("tables-%04d",index),"function_address",h32(c.entry),"category",c.category,"return_defined",!VOIDS.contains(c.entry),
            "oracle_authority","Ghidra EmulatorHelper executing original ELF SLEIGH p-code; not PCS X2 hardware observation");
        try {
            emulator.setMemoryFaultHandler(new MemoryFaultHandler() {
                public boolean unknownAddress(Address at,boolean write){faults.add(obj("type","unknown_address","address",at.toString(true),"write",write));return false;}
                public boolean uninitializedRead(Address at,int size,byte[] buffer,int offset){faults.add(obj("type","uninitialized_read","address",at.toString(true),"size",size));return false;}
            });
            for(String name:REGS)emulator.writeRegister(name+"_qw",BigInteger.ZERO);
            emulator.writeRegister("pc_qw",BigInteger.ZERO);
            emulator.writeRegister("a0",c.a0);emulator.writeRegister("a1",c.a1);emulator.writeRegister("a2",c.a2);emulator.writeRegister("a3",c.a3);
            emulator.writeRegister("ra",RETURN);emulator.writeRegister("sp",SP);emulator.writeRegister(emulator.getPCRegister(),c.entry);
            Map<String,long[]> regions=new LinkedHashMap<>();
            for(Map.Entry<String,Region> item:c.regions.entrySet()) {
                Region r=item.getValue();regions.put(item.getKey(),new long[]{r.base,r.bytes.length});emulator.writeMemory(address(r.base),r.bytes);
            }
            result.put("fixture",obj("snapshot_scope","Only explicitly initialized object/record/string/copy windows and ABI stack; no whole-RAM dump","label_bucket_policy","Lookup fixtures map all 256 buckets to the same initialized collision chain; enumeration and relocation use separately configured sparse buckets","expected_values","No semantic model; original instruction execution only"));
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
        String[] args=getScriptArgs();if(args.length<3 || args.length>4)throw new IllegalArgumentException("Usage: EmulateKamaitachiTables.java <new-output-directory> <original-ELF> <extension-directory> [tables|libc|mmi-strcpy|mmi-strcmp|mmi-template]");
        String group=args.length==4?args[3]:"tables";
        if(currentProgram==null || !LANG.equals(currentProgram.getLanguageID().toString()))throw new IllegalStateException("Requires R5900 current program");
        original=Files.readAllBytes(Path.of(args[1]));if(!SHA.equals(sha(original)) || !SHA.equalsIgnoreCase(String.valueOf(currentProgram.getExecutableSHA256())))throw new IllegalStateException("ELF SHA mismatch");
        ByteBuffer elf=ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);int phoff=elf.getInt(28), count=Short.toUnsignedInt(elf.getShort(44));
        for(int i=0;i<count;i++){int pos=phoff+i*32;if(elf.getInt(pos)==1)loads.add(new long[]{Integer.toUnsignedLong(elf.getInt(pos+8)),Integer.toUnsignedLong(elf.getInt(pos+4)),Integer.toUnsignedLong(elf.getInt(pos+16))});}
        output=Path.of(args[0]).toAbsolutePath().normalize();Path allowedOutput=Path.of(args[1]).toAbsolutePath().normalize().getParent().getParent().getParent().resolve("analysis/ghidra");if(!output.startsWith(allowedOutput))throw new IOException("Oracle output must remain inside project analysis/ghidra");if(Files.exists(output,LinkOption.NOFOLLOW_LINKS))throw new IOException("Refuse existing oracle output");Files.createDirectories(output.getParent());Files.createDirectory(output);
        List<Object> languageFiles=new ArrayList<>();Path extension=Path.of(args[2]);
        for(String name:new String[]{"extension.properties","data/languages/r5900.sla","data/languages/base.sinc","data/languages/mips.sinc","data/languages/r5900.cspec"}){byte[] content=Files.readAllBytes(extension.resolve(name));languageFiles.add(obj("path",name,"sha256",sha(content),"size",content.length));}
        byte[] harness;try(InputStream stream=getSourceFile().getInputStream()){harness=stream.readAllBytes();}Files.write(output.resolve("EmulateKamaitachiTables.java"),harness,StandardOpenOption.CREATE_NEW);
        Map<String,Object> manifest=obj("schema",1,"format","kamaitachi-original-instruction-oracle","status","in_progress","started_utc",Instant.now().toString(),"elf_sha256",SHA,"language_id",LANG,"ghidra_version",Application.getApplicationVersion(),"case_group",group,"harness_sha256",sha(harness),
            "engine","ghidra.app.emulator.EmulatorHelper/currentProgram; SLEIGH p-code","extension_files",languageFiles,"seed",h(SEED),"generator","java.util.Random","cases_file","cases.jsonl","expected_value_source","Only emulator output; no C/C++/Python reference reader formula used",
            "register_defaults","All32 general128-bit _qw registers zeroed before explicit a0/a1/a2/a3/sp/ra/pc assignment; low64 values recorded; void v0 is not a semantic result",
            "guest_layout",obj("self",h32(SELF),"data",h32(DATA),"block",h32(BLOCK),"stack",h32(STACK),"sp",h32(SP),"return_sentinel",h32(RETURN),"records",h32(RECORDS),"label_table",h32(LABELS),"label_record",h32(LABEL),"out",h32(OUT),"snapshot_bases",h32(SNAPSHOTS)),"step_limit",STEP_LIMIT,
            "limits",List.of("Ghidra/SLEIGH oracle, not PCSX2 or original console observation","SLEIGH implementation bugs remain possible; source/language hashes retained","PC samples are EmulatorHelper instruction steps; branch p-code may include delay-slot execution","Synthetic guest objects initialized explicitly, not original game cold heap","No dependencies stubbed; only the declared original-function closure is executed","All unknown/uninitialized reads fail rather than silently initialize zero","Synthetic explicit windows only; no whole game RAM or upstream artifact modification","MMI groups execute the actual unsupported instruction and are failure probes, never valid fixtures","Libc copies execute original forward overlap behavior, not host memmove"));
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
