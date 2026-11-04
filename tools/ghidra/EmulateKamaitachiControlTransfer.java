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
public class EmulateKamaitachiControlTransfer extends GhidraScript {
    private static final String SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final Map<String,String> STATE_RAM=Map.of(
        "46ba269acf9d226ecadfd098e54f38356dda5e4239f3a0579d79a7dcd1860f0f","acc9bf38c3ce3b4d8a4a375f2851425a4bde549881614b40214a474a2e61550c",
        "0c7cdfa175a8a66d26a0b50ddbc9a6cc65ceda561b62bef29a57564eda2dc11f","106c1aaaa95d41cca5f88fced1fdc9a0f40a1d1d0141c755da66accde9b448e6");
    private static final long SP=0x01ff0000L, RETURN=0x003ff000L;
    private static final int LIMIT=100000;
    private static final String[] REGS={"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","s8","ra"};
    private final Gson pretty=new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create();
    private final Gson compact=new GsonBuilder().serializeNulls().disableHtmlEscaping().create();
    private byte[] elf,ram;private JsonObject plan;private Path output;private boolean enhanced,packedHalfword,particlePlatform,cardPlatform,flashPlatform,mimePlatform;
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
        KamaitachiPcpyh pcpyh=packedHalfword?new KamaitachiPcpyh(e):null;
        KamaitachiProjectionVu vu=plan.has("projection_vu")?new KamaitachiProjectionVu(e,elf):null;
        List<Object> faults=new ArrayList<>(),trace=new ArrayList<>();
        Map<String,Object> r=obj("id",c.get("id").getAsString(),"function_address",c.get("function_address").getAsString(),"return_defined",c.get("return_defined").getAsBoolean(),"input",c.get("input"));
        try{
            e.setMemoryFaultHandler(new MemoryFaultHandler(){
                public boolean unknownAddress(Address a,boolean w){faults.add(obj("address",a.toString(true),"write",w,"kind","unknown"));return false;}
                public boolean uninitializedRead(Address a,int s,byte[] b,int o){faults.add(obj("address",a.toString(true),"size",s,"kind","uninitialized"));return false;}
            });
            e.writeMemory(at(0),ram);
            for(JsonElement el:c.getAsJsonObject("input").getAsJsonArray("memory")){JsonObject p=el.getAsJsonObject();e.writeMemory(at(number(p.get("address"))),HexFormat.of().parseHex(p.get("hex").getAsString()));}
            for(String name:REGS)e.writeRegister(name+"_qw",BigInteger.ZERO);
            if(packedHalfword){
                for(int i=0;i<32;i++)e.writeRegister("f"+i,BigInteger.ZERO);
                for(String name:new String[]{"fir","fccr","fexr","fenr","fcsr"})e.writeRegister(name,BigInteger.ZERO);
            }
            e.writeRegister("pc_qw",BigInteger.ZERO);e.writeRegister("gp",0x23daf0);e.writeRegister("sp",SP);e.writeRegister("ra",RETURN);
            for(Map.Entry<String,JsonElement> reg:c.getAsJsonObject("input").getAsJsonObject("registers").entrySet())e.writeRegister(reg.getKey(),number(reg.getValue()));
            e.writeRegister(e.getPCRegister(),number(c.get("function_address")));
            r.put("initial_registers",regs(e));r.put("initial_observed_memory",observe(e));
            e.enableMemoryWriteTracking(true);String status="step_limit";int steps=0;
            boolean semaphoreHeld=false,particleAllocated=false;
            Map<String,Integer> platformCalls=new LinkedHashMap<>();
            for(;steps<LIMIT;++steps){
                monitor.checkCancelled();long pc=e.getExecutionAddress().getOffset();
                if(pc==RETURN){status="returned";break;}
                if(pc<0x100000 || pc+4>0x204b38){status="escaped_original_text";break;}
                byte[] original=Arrays.copyOfRange(elf,(int)pc-0xff000,(int)pc-0xff000+4);
                if(!Arrays.equals(original,e.readMemory(at(pc),4)))throw new IllegalStateException("Runtime instruction differs from original ELF");
                if(flashPlatform && pc==0x17a560){
                    if(particleAllocated || e.readRegister("a0").intValue()!=40 || e.readRegister("a1").intValue()!=0x22ece8 ||
                            e.readRegister("a2").intValue()!=157 || e.readRegister("a3").intValue()!=0 ||
                            e.readRegister("t0").intValue()!=13)throw new IllegalStateException("Unexpected effect_flash.c allocation");
                    particleAllocated=true;
                    long next=e.readRegister("ra").longValue();e.writeRegister("v0",0x1000400);e.writeRegister(e.getPCRegister(),next);
                    platformCalls.merge(h(pc),1,Integer::sum);
                    trace.add(obj("pc",h(pc),"hex",hex(original),"isolated_platform",true,"pc_after",h(next)));
                    continue;
                }
                if(cardPlatform && (pc==0x1b5154 || pc==0x1b5164 || pc==0x1b52a4 || pc==0x1b5284)){
                    int a0=e.readRegister("a0").intValue();
                    int result=0;
                    if(pc==0x1b5154)result=1;
                    else if(pc==0x1b5164){
                        long buffer=e.readRegister("a1").longValue();
                        if(a0!=1 || buffer<SP-0x1000 || buffer>SP-32)throw new IllegalStateException("Unexpected card ReferThreadStatus ABI");
                        e.writeMemory(at(buffer+24),new byte[]{10,0,0,0}); // higher scheduling priority than the source card lock
                    }else if(a0==76){
                        boolean take=pc==0x1b52a4;
                        if(semaphoreHeld==take)throw new IllegalStateException("Unbalanced source card lock #76");
                        semaphoreHeld=take;
                    }else if(a0!=79 || pc!=0x1b5284)throw new IllegalStateException("Unexpected source card worker signal");
                    e.writeRegister("v0",result);e.writeRegister(e.getPCRegister(),pc+4);
                    platformCalls.merge(h(pc),1,Integer::sum);
                    trace.add(obj("pc",h(pc),"hex",hex(original),"isolated_card_kernel",true,"pc_after",h(pc+4)));
                    continue;
                }
                if((particlePlatform || mimePlatform) && (pc==0x17a560 || pc==0x1b5154 || pc==0x1b5164 || pc==0x1b52a4 || pc==0x1b5284)){
                    // Only this one allocation and the four PS2 kernel syscalls
                    // are adapted. MT19937, float generation, semaphores' EE
                    // bookkeeping and all particle instructions execute normally.
                    int a0=e.readRegister("a0").intValue();
                    long next=pc+4;
                    int result=0;
                    if(pc==0x17a560 && mimePlatform){
                        int count=platformCalls.getOrDefault(h(pc),0);
                        if(count>=2 || a0!=(count==0?88:3600) || e.readRegister("a1").intValue()!=0x22ec88 ||
                            e.readRegister("a2").intValue()!=250+count || e.readRegister("a3").intValue()!=0 ||
                            e.readRegister("t0").intValue()!=13)throw new IllegalStateException("Unexpected effect_mime.c allocation");
                        next=e.readRegister("ra").longValue();result=0x1410000+128*count;
                    }else if(pc==0x17a560){
                        if(particleAllocated || e.readRegister("ra").intValue()!=0x1832ec || a0<20 ||
                           a0>0x16000 || (a0-20)%32!=0 || e.readRegister("a1").intValue()!=0x22ee68 ||
                           e.readRegister("a2").intValue()!=138 || e.readRegister("a3").intValue()!=0 ||
                           e.readRegister("t0").intValue()!=13)throw new IllegalStateException("Unexpected original particle allocation");
                        particleAllocated=true;next=e.readRegister("ra").longValue();result=0x1410000;
                    }else if(pc==0x1b5154){result=1;}
                    else if(pc==0x1b5164){
                        long buffer=e.readRegister("a1").longValue();
                        if(a0!=1 || buffer<SP-0x1000 || buffer>SP-32)throw new IllegalStateException("Unexpected ReferThreadStatus ABI");
                        e.writeMemory(at(buffer+24),new byte[]{64,0,0,0});
                    }else{
                        boolean acquire=pc==0x1b52a4;
                        if(a0!=17 || semaphoreHeld==acquire)throw new IllegalStateException("Unexpected particle semaphore acquisition/release");
                        semaphoreHeld=acquire;
                    }
                    e.writeRegister("v0",result);e.writeRegister(e.getPCRegister(),next);
                    platformCalls.merge(h(pc),1,Integer::sum);
                    trace.add(obj("pc",h(pc),"hex",hex(original),"isolated_platform",true,"pc_after",h(next)));
                    continue;
                }
                Instruction instruction=currentProgram.getListing().getInstructionAt(at(pc));
                boolean ok=e.step(monitor);
                trace.add(obj("pc",h(pc),"file_offset",pc-0xff000,"hex",hex(original),"existing_disassembly",instruction==null?null:instruction.toString(),"step_ok",ok,"pc_after",h(e.getExecutionAddress().getOffset())));
                if(!ok){status="emulation_error";steps++;break;}
            }
            if(e.getExecutionAddress().getOffset()==RETURN)status="returned";
            if(particlePlatform || cardPlatform || flashPlatform || mimePlatform){if(semaphoreHeld)throw new IllegalStateException("Unclosed platform semaphore");r.put("isolated_platform_calls",platformCalls);}
            if(!faults.isEmpty())status="memory_fault";
            List<Object> writes=new ArrayList<>();
            for(AddressRange range:e.getTrackedMemoryWriteSet().getAddressRanges()){
                if(!range.getMinAddress().getAddressSpace().getName().equals("ram"))continue;
                long a=range.getMinAddress().getOffset();int size=Math.toIntExact(range.getLength());
                writes.add(obj("address",h(a),"size",size,"role",a>=SP-0x1000&&a+size<=SP+0x100?"stack":"persistent","hex",hex(e.readMemory(at(a),size))));
            }
            r.put("status",status);r.put("steps",steps);r.put("output",obj("registers",regs(e),"memory",observe(e)));
            r.put("tracked_writes",writes);r.put("emulator_error",e.getLastError());
            if(vu!=null)r.put("isolated_vu_instructions",vu.counts);
        }catch(Exception error){r.put("status","harness_exception");r.put("error",error.toString());}
        finally{r.put("trace",trace);r.put("faults",faults);if(mmi!=null){if(pcpyh!=null)mmi.counts.put("_pcpyh",pcpyh.executions);r.put("enhanced_mmi_counts",mmi.counts);}e.dispose();}
        return r;
    }
    @Override public void run()throws Exception{
        String[] a=getScriptArgs();if(a.length<4||a.length>6)throw new IllegalArgumentException("<new-output> <ELF> <plan-json> <extension-directory> [audited-MMI-helper-source [PCPYH-helper-source]]");
        enhanced=a.length>=5;packedHalfword=a.length==6;
        if(!currentProgram.getLanguageID().toString().equals("r5900:LE:32:default"))throw new IllegalStateException("Wrong language");
        elf=Files.readAllBytes(Path.of(a[1]));plan=JsonParser.parseString(Files.readString(Path.of(a[2]))).getAsJsonObject();
        particlePlatform=plan.has("isolated_platform") && plan.get("isolated_platform").getAsString().equals("particle-heap-and-EE-kernel-v1");
        cardPlatform=plan.has("isolated_platform") && plan.get("isolated_platform").getAsString().equals("card-single-owner-slot7-kernel-v1");
        flashPlatform=plan.has("isolated_platform") && plan.get("isolated_platform").getAsString().equals("single-flash-allocation-v1");
        mimePlatform=plan.has("isolated_platform") && plan.get("isolated_platform").getAsString().equals("mesh-heap-and-EE-kernel-v1");
        String state=plan.get("archive_sha256").getAsString();
        if(!sha(elf).equals(SHA)||!SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256())||!SHA.equals(plan.get("elf_sha256").getAsString())||!STATE_RAM.containsKey(state)||!STATE_RAM.get(state).equals(plan.get("ram_sha256").getAsString()))throw new IllegalStateException("Source identity mismatch");
        ram=Files.readAllBytes(Path.of(plan.get("ram_input_path").getAsString()));
        if(ram.length!=0x2000000||!sha(ram).equals(plan.get("ram_sha256").getAsString()))throw new IllegalStateException("Observed RAM identity mismatch");
        if(!Arrays.equals(Arrays.copyOfRange(ram,0x100000,0x204b38),Arrays.copyOfRange(elf,0x1000,0x105b38)))throw new IllegalStateException("Original text mismatch");
        output=Path.of(a[0]).toAbsolutePath().normalize();if(Files.exists(output))throw new IOException("Refuse existing output");Files.createDirectories(output);
        Files.copy(Path.of(a[2]),output.resolve("input-plan.json"));
        byte[] harness;try(InputStream in=getSourceFile().getInputStream()){harness=in.readAllBytes();}Files.write(output.resolve("EmulateKamaitachiControlTransfer.java"),harness,StandardOpenOption.CREATE_NEW);
        List<Object> language=new ArrayList<>();for(String name:new String[]{"extension.properties","data/languages/r5900.sla","data/languages/base.sinc","data/languages/mips.sinc","data/languages/r5900.cspec"}){byte[] b=Files.readAllBytes(Path.of(a[3]).resolve(name));language.add(obj("path",name,"sha256",sha(b)));}
        Map<String,Object> manifest=obj("schema",1,"status","in_progress","engine","Ghidra EmulatorHelper original ELF R5900 SLEIGH","ghidra_version",Application.getApplicationVersion(),"source_elf_sha256",SHA,"source_archive_sha256",state,"source_ram_sha256",sha(ram),"source_plan_sha256",sha(Files.readAllBytes(Path.of(a[2]))),"harness_sha256",sha(harness),"language_files",language,"started_utc",Instant.now().toString(),"expected_value_source","Actual emulated output only; no native/Python transition formula","step_limit",LIMIT,"input_base","Original RAM of the recorded archive, with declared per-case input patches","limits",List.of("Not a PCSX2 hardware observation","SLEIGH bugs remain possible","No source dependency or callback stubs","No metadata/function boundaries created","Guest ABI stack output recorded but excluded from portable core differential"));
        if(enhanced){
            byte[] helper=Files.readAllBytes(Path.of(a[4]));
            Files.write(output.resolve("KamaitachiMmiUserops.java"),helper,StandardOpenOption.CREATE_NEW);
            manifest.put("engine","Ghidra EmulatorHelper original ELF plus isolated audited KamaitachiMmiUserops");
            manifest.put("original_ghidra_mmi_support",false);
            manifest.put("mmi_helper_sha256",sha(helper));manifest.put("mmi_whitelist",KamaitachiMmiUserops.NAMES);
            manifest.put("mmi_validation_reference","analysis/ghidra/mmi-validation-v1/manifest.json;3072 lane vectors and275 actual strcmp executions");
            if(packedHalfword){
                byte[] extra=Files.readAllBytes(Path.of(a[5]));
                Files.write(output.resolve("KamaitachiPcpyh.java"),extra,StandardOpenOption.CREATE_NEW);
                manifest.put("pcpyh_helper_sha256",sha(extra));
                manifest.put("floating_register_initialization","Text fixture explicitly initializes f0..f31 and fir/fccr/fexr/fenr/fcsr to zero, before any per-case input register overrides");
                List<String> names=new ArrayList<>(Arrays.asList(KamaitachiMmiUserops.NAMES));names.add("_pcpyh");
                manifest.put("mmi_whitelist",names);
                manifest.put("pcpyh_instruction_validation",KamaitachiPcpyh.validate(currentProgram,monitor));
                manifest.put("engine","Ghidra EmulatorHelper original ELF plus isolated audited MMI and PCPYH helpers");
            }
        }
        if(plan.has("projection_vu")){
            byte[] helper=Files.readAllBytes(Path.of("tools/ghidra/KamaitachiProjectionVu.java"));
            Files.write(output.resolve("KamaitachiProjectionVu.java"),helper,StandardOpenOption.CREATE_NEW);
            manifest.put("projection_vu_helper_sha256",sha(helper));
            manifest.put("projection_limits","Only the six retail VU0 macro matrix routines use the local disjoint finite-vector adapter; it models lane arithmetic without hardware overflow/fault/timing. Per-op counts included.");
        }
        if(particlePlatform)manifest.put("limits",List.of("Not PCSX2 hardware observation; source EE game math and RNG execute normally",
            "17A560 maps only the checked 183258 allocation to reserved guest RAM",
            "GetThreadId/ReferThreadStatus use one thread, WaitSema/SignalSema one uncontended lock",
            "Every adapted platform call is counted and recorded per case; all other instructions checked against original ELF"));
        if(cardPlatform)manifest.put("limits",List.of("Only four kernel entry instructions adapted for slot7 thread ID 1, priority 10, card lock 76 and worker semaphore 79",
            "All game writers, chart, registry, directory and queue instructions execute from the retail ELF. Disk I/O is outside this function.",
            "Private CPU stack writes excluded from persistent-state comparison; platform calls counted by address"));
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
