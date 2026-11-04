// Original R5900 instruction oracle: real dispatch, real readers, real callbacks.
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
public class EmulateKamaitachiDispatch extends GhidraScript {
    private static final String SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160", LANG="r5900:LE:32:default";
    private static final long MANAGER=0x01f00000L,SCRIPT=0x01f02000L,CONTEXT=0x01f04000L,HANDLER=0x01f06000L,BLOCK=0x01f08000L,DATA=0x01f0a000L;
    private static final long STACK=0x01f0ef80L,SP=0x01f0f000L,RETURN=0x01fffff0L,SEED=0x4b414d4149544143L;
    private static final long CONTEXT_VT=0x2239f0,HANDLER_VT=0x223cc8,ADMISSION=0x206010,HANDLER15=0x1227f0,HANDLER16=0x122808;
    private static final int LIMIT=2048;
    private static final long[] ENTRIES={0x120308,0x1203e0,0x120410,0x120300,0x120250,0x1133a8,0x1133b0,0x1114f0,0x111560,0x10d610,0x10d5d8,HANDLER15,HANDLER16,0x122680};
    private static final String[] REGS={"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","s8","ra"};
    private static final Set<Long> VOID=Set.of(0x1114f0L,0x120250L),WATCH=Set.of(0x1203e0L,0x120410L,HANDLER15,HANDLER16);
    private final Gson pretty=new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create(),compact=new GsonBuilder().serializeNulls().disableHtmlEscaping().create();
    private final AddressSet allowedCode=new AddressSet();private final Set<Long> functionEntries=new HashSet<>(),admitted=new HashSet<>();
    private final List<long[]> loads=new ArrayList<>();private byte[] original;private Path output;
    private static Map<String,Object> obj(Object... a){Map<String,Object> r=new LinkedHashMap<>();for(int i=0;i<a.length;i+=2)r.put((String)a[i],a[i+1]);return r;}
    private void need(boolean condition,String message){if(!condition)throw new IllegalStateException(message);}
    private static String h(long v){return String.format("0x%016x",v);}private static String h32(long v){return String.format("0x%08x",v&0xffffffffL);}
    private static String hex(byte[] b){return HexFormat.of().formatHex(b);}private static String sha(byte[] b)throws Exception{return hex(MessageDigest.getInstance("SHA-256").digest(b));}
    private Address address(long v){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(v&0xffffffffL);}
    private int offset(long a,int n){for(long[] l:loads)if(a>=l[0]&&a-l[0]+n<=l[2])return (int)(l[1]+a-l[0]);throw new IllegalStateException("Not file-backed: "+h32(a));}
    private byte[] source(long a,int n)throws Exception{int off=offset(a,n);byte[] expected=Arrays.copyOfRange(original,off,off+n),actual=new byte[n];need(currentProgram.getMemory().getBytes(address(a),actual)==n&&Arrays.equals(actual,expected),"Source mismatch "+h32(a));return expected;}
    private static void put32(byte[] b,int off,long value){ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(off,(int)value);}
    private static long get32(byte[] b,int off){return Integer.toUnsignedLong(ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getInt(off));}
    private void json(String name,Object value)throws Exception{try(Writer w=Files.newBufferedWriter(output.resolve(name),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)){pretty.toJson(value,w);w.write('\n');}}
    private List<Object> describeFunctions()throws Exception{
        List<Object> result=new ArrayList<>();for(long entry:ENTRIES){Function f=currentProgram.getFunctionManager().getFunctionAt(address(entry));need(f!=null,"Missing exact function "+h32(entry));List<Object> ranges=new ArrayList<>();
            for(AddressRange range:f.getBody().getAddressRanges()){long start=range.getMinAddress().getOffset();int n=Math.toIntExact(range.getLength());byte[] raw=source(start,n);ranges.add(obj("address",h32(start),"length",n,"file_offset",offset(start,n),"hex",hex(raw),"sha256",sha(raw)));}allowedCode.add(f.getBody());functionEntries.add(entry);result.add(obj("function_address",h32(entry),"name",f.getName(),"return_defined",!VOID.contains(entry),"source_ranges",ranges));}return result;
    }
    private List<Object> tables()throws Exception{
        List<Object> result=new ArrayList<>();for(long[] t:new long[][]{{ADMISSION,113*4},{CONTEXT_VT,24},{HANDLER_VT,112}}){byte[] b=source(t[0],(int)t[1]);result.add(obj("address",h32(t[0]),"length",t[1],"file_offset",offset(t[0],(int)t[1]),"hex",hex(b),"sha256",sha(b)));}
        byte[] gate=source(ADMISSION,113*4);for(int i=0;i<113;i++)admitted.add(get32(gate,i*4));need(admitted.size()==113,"Admission uniqueness changed");
        need(get32(source(CONTEXT_VT,24),8)==0x1203e0&&get32(source(HANDLER_VT,112),60)==HANDLER15&&get32(source(HANDLER_VT,112),64)==HANDLER16,"Original vtable identities changed");return result;
    }
    private static class Case{long entry,a1,a2,a3,word=0x12345678L,relative=0;int opcode=5,cursor=3,selector=15;String category;boolean customRelative=false;Case(long e,String c){entry=e;category=c;}}
    private List<Case> cases(){
        List<Case> r=new ArrayList<>();for(int opcode=0;opcode<256;opcode++){Case c=new Case(0x120308,"all-byte-opcodes");c.opcode=opcode;c.cursor=opcode%8;c.selector=new int[]{0,15,49}[opcode%3];r.add(c);}
        long[] edges={0,1,-1,0x7fffffffL,0x80000000L,0xffffffffL,0x100000001L,0xffffffff00000001L};
        for(int opcode:new int[]{5,78,0,255})for(long relative:edges){Case c=new Case(0x120308,"relative-cursor-boundaries");c.opcode=opcode;c.relative=relative;c.customRelative=true;c.cursor=7;c.selector=49;r.add(c);}
        for(long entry:new long[]{0x1203e0,0x120410})for(int n=0;n<edges.length;n++){Case c=new Case(entry,"direct-delegate-register-fidelity");c.a2=edges[n];c.a3=edges[(n+3)%edges.length];r.add(c);}
        for(long entry:new long[]{0x1133a8,0x111560,0x1114f0,0x120300,0x120250})for(long value:edges){Case c=new Case(entry,"manager-context-scalar-boundaries");c.word=value;c.a1=value;r.add(c);}
        for(long index:new long[]{-1,0,1,112,255,256,0x100000001L,0xffffffff00000001L,0x40000000L,0x80000000L,0x7fffffffL}){Case c=new Case(0x1133b0,"handler-lookup-index-register-width");c.a1=index;r.add(c);}return r;
    }
    private Map<String,Object> registers(EmulatorHelper emu){Map<String,Object> r=new LinkedHashMap<>();for(String s:REGS)r.put(s,h(emu.readRegister(s).longValue()));r.put("pc",h32(emu.getExecutionAddress().getOffset()));return r;}
    private List<Object> memory(EmulatorHelper emu,Map<String,long[]> regions){List<Object> r=new ArrayList<>();for(Map.Entry<String,long[]> e:regions.entrySet()){byte[] b=emu.readMemory(address(e.getValue()[0]),(int)e.getValue()[1]);need(b!=null&&b.length==e.getValue()[1],"Short snapshot read");r.add(obj("name",e.getKey(),"address",h32(e.getValue()[0]),"hex",hex(b)));}return r;}
    private Map<String,Object> arguments(EmulatorHelper emu){Map<String,Object> r=new LinkedHashMap<>();for(String s:new String[]{"a0","a1","a2","a3","sp","ra"})r.put(s,h(emu.readRegister(s).longValue()));return r;}
    private Map<String,Object> emulate(Case c,int index)throws Exception{
        EmulatorHelper emu=new EmulatorHelper(currentProgram);List<Object> faults=new ArrayList<>(),trace=new ArrayList<>(),callbacks=new ArrayList<>();ByteArrayOutputStream pcs=new ByteArrayOutputStream();
        Map<String,Object> result=obj("id",String.format("dispatch-%04d",index),"function_address",h32(c.entry),"category",c.category,"return_defined",!VOID.contains(c.entry),"oracle_authority","Original ELF SLEIGH p-code, real subcalls, no callback interception or replacement");
        try{
            emu.setMemoryFaultHandler(new MemoryFaultHandler(){public boolean unknownAddress(Address a,boolean w){faults.add(obj("type","unknown_address","address",a.toString(true),"write",w));return false;}public boolean uninitializedRead(Address a,int n,byte[] b,int off){faults.add(obj("type","uninitialized_read","address",a.toString(true),"size",n));return false;}});
            for(String s:REGS)emu.writeRegister(s+"_qw",BigInteger.ZERO);emu.writeRegister("pc_qw",BigInteger.ZERO);for(int s=0;s<8;s++)emu.writeRegister("s"+s,0x11223300L+s);
            long a0=MANAGER,a1=c.a1;if(Set.of(0x120308L,0x1203e0L,0x120410L,0x120300L,0x120250L).contains(c.entry))a0=CONTEXT;
            if(c.entry==0x120308)a1=MANAGER;if(c.entry==0x1203e0||c.entry==0x120410)a1=HANDLER;
            emu.writeRegister("a0",a0);emu.writeRegister("a1",a1);emu.writeRegister("a2",c.a2);emu.writeRegister("a3",c.a3);emu.writeRegister("v0",0x23456789L);emu.writeRegister("sp",SP);emu.writeRegister("ra",RETURN);emu.writeRegister(emu.getPCRegister(),c.entry);
            Map<String,byte[]> initial=new LinkedHashMap<>();initial.put("manager",new byte[0x500]);initial.put("script",new byte[0x200]);initial.put("context",new byte[16]);initial.put("handler",new byte[16]);initial.put("block",new byte[0x440]);initial.put("data",new byte[32]);initial.put("stack",new byte[256]);
            long[] bases={MANAGER,SCRIPT,CONTEXT,HANDLER,BLOCK,DATA,STACK};Map<String,long[]> regions=new LinkedHashMap<>();Random random=new Random(SEED+index);int regionIndex=0;for(Map.Entry<String,byte[]> e:initial.entrySet()){random.nextBytes(e.getValue());regions.put(e.getKey(),new long[]{bases[regionIndex++],e.getValue().length});}
            byte[] manager=initial.get("manager"),script=initial.get("script"),context=initial.get("context"),handler=initial.get("handler"),block=initial.get("block"),data=initial.get("data");
            put32(manager,0x38,c.entry==0x1133a8?c.word:SCRIPT);put32(manager,0x40,c.entry==0x111560?c.word:CONTEXT);for(int opcode=0;opcode<=256;opcode++)put32(manager,0x5c+opcode*4,HANDLER);
            // Getter-only cases use nonuniform table values; dispatcher always receives a valid original handler object.
            if(c.entry==0x1133b0)for(int n=0;n<=256;n++)put32(manager,0x5c+n*4,0x81000000L+n*0x101L);
            for(int selector=0;selector<50;selector++)put32(script,8+selector*4,BLOCK);put32(script,0xd0,c.selector);put32(script,0xd8,DATA+c.cursor);put32(script,0xdc,DATA+23);
            put32(context,0,c.entry==0x120250?c.word:CONTEXT_VT);put32(handler,0,HANDLER_VT);put32(block,0x430,c.customRelative?DATA+c.cursor-c.relative:DATA);data[c.cursor]=(byte)c.opcode;
            for(Map.Entry<String,byte[]> e:initial.entrySet())emu.writeMemory(address(regions.get(e.getKey())[0]),e.getValue());
            regions.put("original_admission",new long[]{ADMISSION,452});regions.put("original_context_vtable",new long[]{CONTEXT_VT,24});regions.put("original_handler_vtable",new long[]{HANDLER_VT,112});
            result.put("input",obj("registers",registers(emu),"memory",memory(emu,regions)));result.put("setup",obj("opcode",c.opcode,"selector",c.selector,"cursor_byte_offset",c.cursor,"original_gate_admits_opcode",admitted.contains((long)c.opcode),"synthetic_objects",true));
            emu.enableMemoryWriteTracking(true);String status="step_limit";int steps=0;
            for(;steps<LIMIT;steps++){
                monitor.checkCancelled();Address pc=emu.getExecutionAddress();long rawpc=pc.getOffset();if(pc.equals(address(RETURN))){status="returned";break;}if(!allowedCode.contains(pc)){status="escaped_known_original_functions";break;}
                Instruction ins=currentProgram.getListing().getInstructionAt(pc);if(ins==null){status="undefined_original_instruction";break;}byte[] raw=source(rawpc,ins.getLength());pcs.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt((int)rawpc).array());
                if(WATCH.contains(rawpc))callbacks.add(obj("entry",h32(rawpc),"step",steps,"is_test_entry",steps==0,"registers",arguments(emu)));
                boolean record=functionEntries.contains(rawpc)||ins.getFlowType().isComputed();Map<String,Object> before=record?obj("pc_before",h32(rawpc),"file_offset",offset(rawpc,raw.length),"hex",hex(raw),"disassembly",ins.toString(),"registers_before",arguments(emu)):null;
                boolean ok=emu.step(monitor);if(record){before.put("pc_after",h32(emu.getExecutionAddress().getOffset()));before.put("step_ok",ok);trace.add(before);}if(!ok){status="emulation_error";steps++;break;}
            }
            if(emu.getExecutionAddress().equals(address(RETURN)))status="returned";if(!faults.isEmpty())status="memory_fault";
            result.put("status",status);result.put("steps",steps);result.put("output",obj("registers",registers(emu),"memory",memory(emu,regions)));result.put("trace",trace);result.put("callback_entries",callbacks);result.put("pc_trace_le32_hex",hex(pcs.toByteArray()));result.put("faults",faults);result.put("emulator_error",emu.getLastError());
            List<Object> writes=new ArrayList<>();AddressSet mutable=new AddressSet();for(Map.Entry<String,long[]> region:regions.entrySet())if(!region.getKey().startsWith("original_"))mutable.add(address(region.getValue()[0]),address(region.getValue()[0]+region.getValue()[1]-1));
            for(AddressRange range:emu.getTrackedMemoryWriteSet().getAddressRanges()){writes.add(obj("start",range.getMinAddress().toString(true),"end_inclusive",range.getMaxAddress().toString(true),"length",range.getLength()));if(range.getMinAddress().getAddressSpace().equals(address(0).getAddressSpace()))need(mutable.contains(range.getMinAddress(),range.getMaxAddress()),"Write outside declared mutable snapshots");}result.put("tracked_writes",writes);
            if(status.equals("returned")){
                need(emu.readRegister("sp").longValue()==SP&&emu.readRegister("ra").longValue()==RETURN,"SP/RA not restored");for(int s=0;s<8;s++)need(emu.readRegister("s"+s).longValue()==0x11223300L+s,"Callee-saved register changed");
                long handlers=callbacks.stream().filter(x->((Map<?,?>)x).get("entry").equals(h32(HANDLER15))||((Map<?,?>)x).get("entry").equals(h32(HANDLER16))).count();
                if(c.entry==0x120308)need(handlers==(admitted.contains((long)c.opcode)?1:0),"Admission/callback observation mismatch");if(c.entry==0x1203e0||c.entry==0x120410)need(handlers==1,"Direct delegate did not execute real handler");
                result.put("observations",obj("handler_entry_count",handlers,"cursor_after",h32(get32(emu.readMemory(address(SCRIPT),0x200),0xd8)),"manager_context_after",h32(get32(emu.readMemory(address(MANAGER),0x500),0x40)),"context_vtable_after",h32(get32(emu.readMemory(address(CONTEXT),16),0))));
            }
        }catch(Exception ex){result.put("status","harness_exception");result.put("error",ex.toString());result.put("faults",faults);result.put("trace",trace);result.put("callback_entries",callbacks);result.put("pc_trace_le32_hex",hex(pcs.toByteArray()));}
        finally{emu.dispose();}return result;
    }
    @Override public void run()throws Exception{
        String[] a=getScriptArgs();need(a.length==3,"Usage: <new-output> <original-ELF> <extension-directory>");need(currentProgram!=null&&LANG.equals(currentProgram.getLanguageID().toString()),"Wrong language");original=Files.readAllBytes(Path.of(a[1]));need(SHA.equals(sha(original))&&SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()),"ELF/program identity mismatch");
        ByteBuffer elf=ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);int ph=elf.getInt(28),count=Short.toUnsignedInt(elf.getShort(44));for(int i=0;i<count;i++){int p=ph+i*32;if(elf.getInt(p)==1)loads.add(new long[]{Integer.toUnsignedLong(elf.getInt(p+8)),Integer.toUnsignedLong(elf.getInt(p+4)),Integer.toUnsignedLong(elf.getInt(p+16))});}
        output=Path.of(a[0]);need(!Files.exists(output),"Output already exists");Files.createDirectories(output);byte[] harness;try(InputStream in=getSourceFile().getInputStream()){harness=in.readAllBytes();}Files.write(output.resolve("EmulateKamaitachiDispatch.java"),harness);
        List<Object> languages=new ArrayList<>();for(String name:new String[]{"extension.properties","data/languages/r5900.sla","data/languages/base.sinc","data/languages/mips.sinc","data/languages/r5900.cspec"}){byte[] b=Files.readAllBytes(Path.of(a[2]).resolve(name));languages.add(obj("path",name,"sha256",sha(b),"size",b.length));}
        Map<String,Object> manifest=obj("schema",1,"format","kamaitachi-original-instruction-oracle","status","in_progress","started_utc",Instant.now().toString(),"elf_sha256",SHA,"language_id",LANG,"ghidra_version",Application.getApplicationVersion(),"engine","ghidra.app.emulator.EmulatorHelper/currentProgram; original SLEIGH p-code","case_group","dispatch","harness_sha256",sha(harness),"extension_files",languages,"seed",h(SEED),"generator","java.util.Random","cases_file","cases.jsonl","step_limit",LIMIT,"expected_value_source","Only actual original instruction output; no C++ or reference dispatcher output generator",
            "guest_layout",obj("manager",h32(MANAGER),"script",h32(SCRIPT),"context",h32(CONTEXT),"handler",h32(HANDLER),"block",h32(BLOCK),"data",h32(DATA),"stack",h32(STACK),"sp",h32(SP),"return_sentinel",h32(RETURN)),
            "trace_policy","trace contains original function entry and computed-flow steps; pc_trace_le32_hex contains every original step PC as concatenated little-endian uint32; delay slots may execute within a step",
            "limits",List.of("Synthetic objects, not original cold heap","Every callback target executes original instructions; no hooks, stubs, patched vtables or replacement return values","Handler slot15/16 use real return-zero wrappers; nonzero/blocking handler propagation is not covered","Admission table and both vtables come from unchanged original ELF; manager handler slots deliberately reference one valid handler","Unknown/uninitialized memory is a failure","Ghidra/SLEIGH oracle, not PS2 hardware or full-game observation","Void setters retain observed v0 without treating it as semantic return"));
        int total=0,returned=0;List<Object> failed=new ArrayList<>();json("started.json",manifest);
        try{manifest.put("functions",describeFunctions());manifest.put("original_tables",tables());manifest.put("admitted_opcodes",new TreeSet<>(admitted));List<Case> cases=cases();manifest.put("planned_cases",cases.size());
            try(Writer w=Files.newBufferedWriter(output.resolve("cases.jsonl"),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)){for(Case c:cases){Map<String,Object> result=emulate(c,total++);compact.toJson(result,w);w.write('\n');w.flush();if(result.get("status").equals("returned"))returned++;else{failed.add(obj("id",result.get("id"),"entry",result.get("function_address"),"status",result.get("status"),"error",result.get("error"),"emulator_error",result.get("emulator_error")));break;}if(total%64==0)println("Dispatch oracle "+total+"/"+cases.size());}}
            manifest.put("status",total==cases.size()&&failed.isEmpty()?"oracle_completed":"oracle_failed");need(SHA.equals(sha(Files.readAllBytes(Path.of(a[1])))),"Original ELF changed");
        }catch(Exception ex){manifest.put("status","oracle_failed");manifest.put("error",ex.toString());throw ex;}
        finally{manifest.put("case_count",total);manifest.put("returned_count",returned);manifest.put("failed",failed);manifest.put("finished_utc",Instant.now().toString());if(Files.exists(output.resolve("cases.jsonl")))manifest.put("cases_sha256",sha(Files.readAllBytes(output.resolve("cases.jsonl"))));json("manifest.json",manifest);}
        println("Dispatch oracle "+manifest.get("status")+" "+returned+"/"+total);
    }
}
