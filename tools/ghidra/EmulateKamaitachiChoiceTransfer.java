// Execute the original transfer and its real callees on observed EE state.
// @category Kamaitachi.Evidence
import java.io.*;
import java.math.BigInteger;
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
import ghidra.program.model.listing.Instruction;

@SuppressWarnings("removal")
public class EmulateKamaitachiChoiceTransfer extends GhidraScript {
    private static final String SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final String STATE="46ba269acf9d226ecadfd098e54f38356dda5e4239f3a0579d79a7dcd1860f0f";
    private static final long SP=0x01ff0000L, RETURN=0x003ff000L;
    private static final int LIMIT=100000;
    private static final String[] REGS={"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","s8","ra"};
    private final Gson pretty=new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create();
    private final Gson compact=new GsonBuilder().serializeNulls().disableHtmlEscaping().create();
    private byte[] elf,ram;private JsonObject plan;private Path output;private boolean enhanced;
    private static Map<String,Object> obj(Object... a){Map<String,Object> m=new LinkedHashMap<>();for(int i=0;i<a.length;i+=2)m.put((String)a[i],a[i+1]);return m;}
    private static String hex(byte[] b){return HexFormat.of().formatHex(b);}
    private static String sha(byte[] b)throws Exception{return hex(MessageDigest.getInstance("SHA-256").digest(b));}
    private static String h(long v){return String.format("0x%08x",v);}
    private static long number(JsonElement e){return Long.parseUnsignedLong(e.getAsString().replace("0x",""),16);}
    private Address at(long a){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);}
    private void write(String name,Object d)throws Exception{try(Writer w=Files.newBufferedWriter(output.resolve(name),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)){pretty.toJson(d,w);w.write('\n');}}
    private List<Object> observe(EmulatorHelper e){
        List<Object> r=new ArrayList<>();
        for(JsonElement el:plan.getAsJsonArray("observed_regions")){
            JsonObject region=el.getAsJsonObject();long a=number(region.get("address"));int size=region.get("size").getAsInt();
            r.add(obj("name",region.get("name").getAsString(),"address",h(a),"hex",hex(e.readMemory(at(a),size))));
        }
        r.add(obj("name","stack","address",h(SP-0x1000),"hex",hex(e.readMemory(at(SP-0x1000),0x1100))));
        return r;
    }
    private Map<String,Object> regs(EmulatorHelper e){Map<String,Object> r=new LinkedHashMap<>();for(String n:REGS)r.put(n,String.format("0x%016x",e.readRegister(n).longValue()));r.put("pc",h(e.getExecutionAddress().getOffset()));return r;}
    private Map<String,Object> emulate(JsonObject c)throws Exception{
        EmulatorHelper e=new EmulatorHelper(currentProgram);
        KamaitachiMmiUserops mmi=enhanced?new KamaitachiMmiUserops(e):null;
        List<Object> faults=new ArrayList<>(),trace=new ArrayList<>();
        Map<String,Object> r=obj("id",c.get("id").getAsString(),"function_address",c.get("function_address").getAsString(),"return_defined",false,"input",c.get("input"));
        try{
            e.setMemoryFaultHandler(new MemoryFaultHandler(){
                public boolean unknownAddress(Address a,boolean w){faults.add(obj("address",a.toString(true),"write",w,"kind","unknown"));return false;}
                public boolean uninitializedRead(Address a,int s,byte[] b,int o){faults.add(obj("address",a.toString(true),"size",s,"kind","uninitialized"));return false;}
            });
            e.writeMemory(at(0),ram);
            for(JsonElement el:c.getAsJsonObject("input").getAsJsonArray("memory")){JsonObject p=el.getAsJsonObject();e.writeMemory(at(number(p.get("address"))),HexFormat.of().parseHex(p.get("hex").getAsString()));}
            for(String name:REGS)e.writeRegister(name+"_qw",BigInteger.ZERO);
            e.writeRegister("pc_qw",BigInteger.ZERO);e.writeRegister("gp",0x23daf0);e.writeRegister("sp",SP);e.writeRegister("ra",RETURN);
            for(Map.Entry<String,JsonElement> reg:c.getAsJsonObject("input").getAsJsonObject("registers").entrySet())e.writeRegister(reg.getKey(),number(reg.getValue()));
            e.writeRegister(e.getPCRegister(),number(c.get("function_address")));
            r.put("initial_registers",regs(e));r.put("initial_observed_memory",observe(e));
            e.enableMemoryWriteTracking(true);String status="step_limit";int steps=0;
            for(;steps<LIMIT;++steps){
                monitor.checkCancelled();long pc=e.getExecutionAddress().getOffset();
                if(pc==RETURN){status="returned";break;}
                if(pc<0x100000 || pc+4>0x204b38){status="escaped_original_text";break;}
                byte[] original=Arrays.copyOfRange(elf,(int)pc-0xff000,(int)pc-0xff000+4);
                if(!Arrays.equals(original,e.readMemory(at(pc),4)))throw new IllegalStateException("Runtime instruction differs from original ELF");
                Instruction instruction=currentProgram.getListing().getInstructionAt(at(pc));
                boolean ok=e.step(monitor);
                trace.add(obj("pc",h(pc),"file_offset",pc-0xff000,"hex",hex(original),"existing_disassembly",instruction==null?null:instruction.toString(),"step_ok",ok,"pc_after",h(e.getExecutionAddress().getOffset())));
                if(!ok){status="emulation_error";steps++;break;}
            }
            if(e.getExecutionAddress().getOffset()==RETURN)status="returned";
            if(!faults.isEmpty())status="memory_fault";
            List<Object> writes=new ArrayList<>();
            for(AddressRange range:e.getTrackedMemoryWriteSet().getAddressRanges()){
                long a=range.getMinAddress().getOffset();int size=Math.toIntExact(range.getLength());
                writes.add(obj("address",h(a),"size",size,"role",a>=SP-0x1000&&a+size<=SP+0x100?"stack":"persistent","hex",hex(e.readMemory(at(a),size))));
            }
            r.put("status",status);r.put("steps",steps);r.put("output",obj("registers",regs(e),"memory",observe(e)));
            r.put("tracked_writes",writes);r.put("emulator_error",e.getLastError());
        }catch(Exception error){r.put("status","harness_exception");r.put("error",error.toString());}
        finally{r.put("trace",trace);r.put("faults",faults);if(mmi!=null)r.put("enhanced_mmi_counts",mmi.counts);e.dispose();}
        return r;
    }
    @Override public void run()throws Exception{
        String[] a=getScriptArgs();if(a.length<4||a.length>5)throw new IllegalArgumentException("<new-output> <ELF> <plan-json> <extension-directory> [audited-MMI-helper-source]");
        enhanced=a.length==5;
        if(!currentProgram.getLanguageID().toString().equals("r5900:LE:32:default"))throw new IllegalStateException("Wrong language");
        elf=Files.readAllBytes(Path.of(a[1]));plan=JsonParser.parseString(Files.readString(Path.of(a[2]))).getAsJsonObject();
        if(!sha(elf).equals(SHA)||!SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())||!SHA.equals(plan.get("elf_sha256").getAsString())||!STATE.equals(plan.get("archive_sha256").getAsString()))throw new IllegalStateException("Source identity mismatch");
        ram=Files.readAllBytes(Path.of(plan.get("ram_input_path").getAsString()));
        if(ram.length!=0x2000000||!sha(ram).equals(plan.get("ram_sha256").getAsString()))throw new IllegalStateException("Observed RAM identity mismatch");
        if(!Arrays.equals(Arrays.copyOfRange(ram,0x100000,0x204b38),Arrays.copyOfRange(elf,0x1000,0x105b38)))throw new IllegalStateException("Original text mismatch");
        output=Path.of(a[0]).toAbsolutePath().normalize();if(Files.exists(output))throw new IOException("Refuse existing output");Files.createDirectories(output);
        Files.copy(Path.of(a[2]),output.resolve("input-plan.json"));
        byte[] harness;try(InputStream in=getSourceFile().getInputStream()){harness=in.readAllBytes();}Files.write(output.resolve("EmulateKamaitachiChoiceTransfer.java"),harness,StandardOpenOption.CREATE_NEW);
        List<Object> language=new ArrayList<>();for(String name:new String[]{"extension.properties","data/languages/r5900.sla","data/languages/base.sinc","data/languages/mips.sinc","data/languages/r5900.cspec"}){byte[] b=Files.readAllBytes(Path.of(a[3]).resolve(name));language.add(obj("path",name,"sha256",sha(b)));}
        Map<String,Object> manifest=obj("schema",1,"status","in_progress","engine","Ghidra EmulatorHelper original ELF R5900 SLEIGH","ghidra_version",Application.getApplicationVersion(),"source_elf_sha256",SHA,"source_archive_sha256",STATE,"source_ram_sha256",sha(ram),"source_plan_sha256",sha(Files.readAllBytes(Path.of(a[2]))),"harness_sha256",sha(harness),"language_files",language,"started_utc",Instant.now().toString(),"expected_value_source","Actual emulated output only; no native/Python transition formula","step_limit",LIMIT,"input_base","Original slot7 RAM, with declared per-case input patches","limits",List.of("Not a PCSX2 hardware observation","SLEIGH bugs remain possible","No source dependency or callback stubs","No metadata/function boundaries created","Guest ABI stack output recorded but excluded from portable core differential"));
        if(enhanced){
            byte[] helper=Files.readAllBytes(Path.of(a[4]));
            Files.write(output.resolve("KamaitachiMmiUserops.java"),helper,StandardOpenOption.CREATE_NEW);
            manifest.put("engine","Ghidra EmulatorHelper original ELF plus isolated audited KamaitachiMmiUserops");
            manifest.put("original_ghidra_mmi_support",false);
            manifest.put("mmi_helper_sha256",sha(helper));manifest.put("mmi_whitelist",KamaitachiMmiUserops.NAMES);
            manifest.put("mmi_validation_reference","analysis/ghidra/mmi-validation-v1/manifest.json;3072 lane vectors and275 actual strcmp executions");
        }
        write("started.json",manifest);int total=0,returned=0;List<Object> failed=new ArrayList<>();
        try(Writer writer=Files.newBufferedWriter(output.resolve("cases.jsonl"),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)){
            for(JsonElement el:plan.getAsJsonArray("cases")){
                Map<String,Object> result=emulate(el.getAsJsonObject());compact.toJson(result,writer);writer.write('\n');writer.flush();total++;
                if("returned".equals(result.get("status")))returned++;else{failed.add(obj("id",result.get("id"),"status",result.get("status"),"error",result.get("error"),"emulator_error",result.get("emulator_error")));break;}
                if(total%3==0)println("Transfer oracle returned "+returned);
            }
        }finally{manifest.put("status",total==plan.getAsJsonArray("cases").size()&&failed.isEmpty()?"oracle_completed":"oracle_failed");manifest.put("case_count",total);manifest.put("returned_count",returned);manifest.put("failed",failed);manifest.put("finished_utc",Instant.now().toString());manifest.put("cases_sha256",sha(Files.readAllBytes(output.resolve("cases.jsonl"))));write("manifest.json",manifest);}
        println("Transfer oracle "+manifest.get("status")+" "+returned+"/"+total);
    }
}
