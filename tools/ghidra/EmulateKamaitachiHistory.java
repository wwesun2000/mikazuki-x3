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
public class EmulateKamaitachiHistory extends GhidraScript {
    private static final String SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final String LANG="r5900:LE:32:default";
    private static final long SELF=0x01f00000L, DATA=0x01f02000L, BLOCK=0x01f04000L;
    private static final long RECORDS=0x01e00000L, LABELS=0x01d00000L, LABEL=0x01f06000L, OUT=0x01f08000L, SNAPSHOTS=0x01c00000L;
    private static final long STACK=0x01f0ee00L, SP=0x01f0f000L, RETURN=0x01fffff0L;
    private static final long SEED=0x4b414d4149544143L;
    private static final int STEP_LIMIT=1024;
    private static final long[] ENTRIES={0x10d3d0,0x10d3e8,0x10d750,0x10dae8,0x10daf0,0x10e630,0x10e640,0x10e658,0x10e708,0x10e748,0x10e878,0x10e8d8,0x10e9d8,0x10edc0,0x10edf0,0x10eea0,0x10eed0,0x10eee8,0x10ef18,0x10ef48,0x10ef60,0x10ef90,0x10eff0,0x10f100,0x10f898,0x10fa28,0x10fa68,0x10fab8,0x10fac0,0x10fac8,0x10d748,0x10d830,0x10d738,0x10d700,0x10d780};
    private static final Set<Long> VOIDS=Set.of(0x10f100L,0x10fab8L,0x10fac8L,0x10d830L,0x10d738L,0x10d700L,0x10d780L);
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
    private static class Case {
        String category; long entry,a1,a2,a3; int recordId=1,labelId=1,selector=15,word0=0,word1=0,savedValid=1,savedId=1,savedSelector=7,savedLabel=123,depth=0,flag=0,labelOffset=3;
        Case(long entry,String category,long a1,long a2,long a3){this.entry=entry;this.category=category;this.a1=a1;this.a2=a2;this.a3=a3;}
    }
    private List<Case> cases() {
        List<Case> result=new ArrayList<>();Random random=new Random(SEED);
        int[] ids={0,1,6565,6566,16382,16383};
        long[] edge={0,1,30,31,32,63,0x3ffe,0x3fff,0x4000,0x7fffffffL,0x80000000L,0xffffffffL,0x100000001L};
        int[] words={0,-1,0x55555555,0xaaaaaaaa,0x80000000,0x40000000,0x20000000,0x10000000};
        long[] recordEntries={0x10e658,0x10e878,0x10e748,0x10e8d8,0x10e9d8,0x10edc0,0x10edf0,0x10eea0,0x10eed0,0x10eee8,0x10ef18,0x10ef48,0x10ef60,0x10ef90,0x10eff0};
        for(long entry:recordEntries)for(int i=0;i<24;i++) {
            int id=ids[i%ids.length];boolean writer=entry==0x10e658 || entry==0x10e878;
            Case c=new Case(entry,writer?"history-field-masks":"history-bit-patterns",id,writer?edge[i%edge.length]:OUT,writer?edge[(i*3)%edge.length]:OUT+4);
            c.recordId=id;c.word0=i<words.length?words[i]:random.nextInt();c.word1=i<words.length?words[(i+3)%words.length]:random.nextInt();result.add(c);
        }
        for(long entry:new long[]{0x10e748,0x10e8d8})for(int id:new int[]{0,1,16383})for(int mode=0;mode<9;mode++) {
            long record=RECORDS+id*8L;long[][] pointers={{0,0},{OUT,0},{0,OUT},{OUT,OUT},{record,record+4},{record+4,record},{SELF+0x178,SELF+0x17c},{record,record},{SELF+0x17c,SELF+0x178}};
            Case c=new Case(entry,"getter-output-alias-"+mode,id,pointers[mode][0],pointers[mode][1]);c.recordId=id;c.word0=random.nextInt();c.word1=random.nextInt();result.add(c);
        }
        for(int valid:new int[]{0,1,-1})for(long requested:new long[]{1,2,0x100000001L,0xffffffff00000001L})for(int mode=0;mode<7;mode++) {
            long[][] pointers={{0,0},{OUT,0},{0,OUT},{OUT,OUT},{SELF+0x178,SELF+0x17c},{SELF+0x17c,SELF+0x178},{SELF+0x170,SELF+0x174}};
            Case c=new Case(0x10e708,"saved-history-output-alias-"+mode,requested,pointers[mode][0],pointers[mode][1]);c.savedValid=valid;c.savedSelector=random.nextInt();c.savedLabel=random.nextInt();result.add(c);
        }
        for(long entry:new long[]{0x10f898,0x10fa28,0x10fa68,0x10d750,0x10daf0})for(int id:ids)for(int offset:new int[]{0,-1,1,0x7fffffff,0x80000000}) {
            Case c=new Case(entry,"label-pointer-offset-boundary",entry==0x10daf0?(id%50):id,entry==0x10daf0?id:0,0);c.labelId=id;c.labelOffset=offset;result.add(c);
        }
        for(long entry:new long[]{0x10d3d0,0x10d3e8,0x10e630,0x10e640})for(long id:new long[]{-1,0,1,6565,16383,0x7fffffffL,0x80000000L,0xffffffffL,0x100000001L})for(int table:new int[]{0,1,2})result.add(new Case(entry,"pointer-arithmetic-no-dereference",id,table,0));
        for(long entry:new long[]{0x10f100,0x10fab8,0x10fac0,0x10fac8})for(long value:edge){Case c=new Case(entry,"scalar-state-boundary",value,0,0);c.depth=(int)value;c.flag=(int)value;result.add(c);}
        result.add(new Case(0x10dae8,"constant-source-return",0,0,0));
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
        Map<String,Object> result=obj("id",String.format("history-%04d",index),"function_address",h32(c.entry),"category",c.category,"return_defined",!VOIDS.contains(c.entry),
            "oracle_authority","Ghidra EmulatorHelper executing original ELF SLEIGH p-code; not PCS X2 hardware observation");
        try {
            emulator.setMemoryFaultHandler(new MemoryFaultHandler() {
                public boolean unknownAddress(Address at,boolean write){faults.add(obj("type","unknown_address","address",at.toString(true),"write",write));return false;}
                public boolean uninitializedRead(Address at,int size,byte[] buffer,int offset){faults.add(obj("type","uninitialized_read","address",at.toString(true),"size",size));return false;}
            });
            for(String name:REGS)emulator.writeRegister(name+"_qw",BigInteger.ZERO);
            emulator.writeRegister("pc_qw",BigInteger.ZERO);
            emulator.writeRegister("a0",SELF);emulator.writeRegister("a1",c.a1);emulator.writeRegister("a2",c.a2);emulator.writeRegister("a3",c.a3);
            emulator.writeRegister("ra",RETURN);emulator.writeRegister("sp",SP);emulator.writeRegister(emulator.getPCRegister(),c.entry);
            byte[] self=new byte[0x200],data=new byte[128],block=new byte[0x440],stack=new byte[0x400],records=new byte[24],labels=new byte[12],label=new byte[64],out=new byte[16];
            Random random=new Random(SEED+index);for(byte[] region:new byte[][]{self,data,block,stack,records,labels,label,out})random.nextBytes(region);
            for(int selector=0;selector<50;selector++)put32(self,8+selector*4,BLOCK);
            put32(self,0xcc,LABELS);put32(self,0xd0,c.selector);put32(self,0xd4,c.entry==0x10d750?c.labelId:c.recordId);put32(self,0xd8,DATA+3);put32(self,0xdc,DATA+7);
            put32(self,0x138,RECORDS);for(int i=0;i<3;i++)put32(self,0x13c+i*4,SNAPSHOTS+i*0x10000L);
            put32(self,0x148,c.depth);put32(self,0x168,c.flag);put32(self,0x170,c.savedValid);put32(self,0x174,c.savedId);put32(self,0x178,c.savedSelector);put32(self,0x17c,c.savedLabel);
            put32(block,0x430,DATA);put32(records,8,c.word0);put32(records,12,c.word1);put32(labels,4,LABEL);put32(label,4,c.labelOffset);
            byte[] name="pr01_0020\0".getBytes(StandardCharsets.US_ASCII);System.arraycopy(name,0,label,8,name.length);
            Map<String,long[]> regions=new LinkedHashMap<>();
            regions.put("self",new long[]{SELF,self.length});regions.put("data",new long[]{DATA,data.length});regions.put("block",new long[]{BLOCK,block.length});
            regions.put("records",new long[]{RECORDS+(c.recordId-1L)*8,records.length});regions.put("label_table",new long[]{LABELS+(c.labelId-1L)*4,labels.length});regions.put("label_record",new long[]{LABEL,label.length});regions.put("out",new long[]{OUT,out.length});regions.put("stack",new long[]{STACK,stack.length});
            byte[][] buffers={self,data,block,records,labels,label,out,stack};int bi=0;for(long[] region:regions.values())emulator.writeMemory(address(region[0]),buffers[bi++]);
            result.put("fixture",obj("record_id",c.recordId,"label_id",c.labelId,"record_address",h32(RECORDS+c.recordId*8L),"label_table_cell",h32(LABELS+c.labelId*4L),"snapshot_scope","Complete self/block/data/label_record/out/stack; only selected record plus adjacent record canaries and label pointer plus adjacent pointer canaries"));
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
        String[] args=getScriptArgs();if(args.length!=3)throw new IllegalArgumentException("Usage: EmulateKamaitachiHistory.java <new-output-directory> <original-ELF> <extension-directory>");
        String group="history-label";
        if(currentProgram==null || !LANG.equals(currentProgram.getLanguageID().toString()))throw new IllegalStateException("Requires R5900 current program");
        original=Files.readAllBytes(Path.of(args[1]));if(!SHA.equals(sha(original)) || !SHA.equalsIgnoreCase(String.valueOf(currentProgram.getExecutableSHA256())))throw new IllegalStateException("ELF SHA mismatch");
        ByteBuffer elf=ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);int phoff=elf.getInt(28), count=Short.toUnsignedInt(elf.getShort(44));
        for(int i=0;i<count;i++){int pos=phoff+i*32;if(elf.getInt(pos)==1)loads.add(new long[]{Integer.toUnsignedLong(elf.getInt(pos+8)),Integer.toUnsignedLong(elf.getInt(pos+4)),Integer.toUnsignedLong(elf.getInt(pos+16))});}
        output=Path.of(args[0]).toAbsolutePath().normalize();if(Files.exists(output,LinkOption.NOFOLLOW_LINKS))throw new IOException("Refuse existing oracle output");Files.createDirectories(output.getParent());Files.createDirectory(output);
        List<Object> languageFiles=new ArrayList<>();Path extension=Path.of(args[2]);
        for(String name:new String[]{"extension.properties","data/languages/r5900.sla","data/languages/base.sinc","data/languages/mips.sinc","data/languages/r5900.cspec"}){byte[] content=Files.readAllBytes(extension.resolve(name));languageFiles.add(obj("path",name,"sha256",sha(content),"size",content.length));}
        byte[] harness;try(InputStream stream=getSourceFile().getInputStream()){harness=stream.readAllBytes();}Files.write(output.resolve("EmulateKamaitachiHistory.java"),harness,StandardOpenOption.CREATE_NEW);
        Map<String,Object> manifest=obj("schema",1,"format","kamaitachi-original-instruction-oracle","status","in_progress","started_utc",Instant.now().toString(),"elf_sha256",SHA,"language_id",LANG,"ghidra_version",Application.getApplicationVersion(),"case_group",group,"harness_sha256",sha(harness),
            "engine","ghidra.app.emulator.EmulatorHelper/currentProgram; SLEIGH p-code","extension_files",languageFiles,"seed",h(SEED),"generator","java.util.Random","cases_file","cases.jsonl","expected_value_source","Only emulator output; no C/C++/Python reference reader formula used",
            "register_defaults","All32 general128-bit _qw registers zeroed before explicit a0/a1/a2/a3/sp/ra/pc assignment; low64 values recorded; void v0 is not a semantic result",
            "guest_layout",obj("self",h32(SELF),"data",h32(DATA),"block",h32(BLOCK),"stack",h32(STACK),"sp",h32(SP),"return_sentinel",h32(RETURN),"records",h32(RECORDS),"label_table",h32(LABELS),"label_record",h32(LABEL),"out",h32(OUT),"snapshot_bases",h32(SNAPSHOTS)),"step_limit",STEP_LIMIT,
            "limits",List.of("Ghidra/SLEIGH oracle, not PCSX2 or original console observation","SLEIGH implementation bugs remain possible; source/language hashes retained","PC samples are EmulatorHelper instruction steps; branch p-code may include delay-slot execution","Synthetic guest objects initialized explicitly, not original game cold heap","No dependencies stubbed; only the declared original-function closure is executed","All unknown/uninitialized reads fail rather than silently initialize zero","Sparse record/table windows are synthetic fixtures, not full game record-table initialization; adjacent record canaries retained"));
        int returned=0,total=0;List<Object> failed=new ArrayList<>();
        json("started.json",manifest);
        try {
            manifest.put("functions",describeFunctions());List<Case> cases=cases();manifest.put("planned_cases",cases.size());
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
