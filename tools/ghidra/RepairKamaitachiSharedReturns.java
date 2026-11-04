// Fixed-build, evidence-guided metadata repair. Original bytes are never written.
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
import ghidra.app.cmd.analysis.SharedReturnAnalysisCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

@SuppressWarnings("removal")
public class RepairKamaitachiSharedReturns extends GhidraScript {
    private static final String SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final long[][] GROUPS={{0x122680,0x223cc8},{0x126fc0,0x224278},{0x130348,0x225468},{0x133180,0x225938}};
    private static final long[] CONTEXT={0x120300,0x120308,0x1203e0,0x120410,0x120250,0x120260};
    private static final String[] REGS={"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","s8","ra"};
    private final Gson gson=new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create();
    private final Gson compact=new GsonBuilder().serializeNulls().disableHtmlEscaping().create();
    private byte[] original; private Path output,root; private final List<long[]> loads=new ArrayList<>();
    private final Set<Address> allowedOwners=new HashSet<>(),allowedFlows=new HashSet<>(),allowedNew=new HashSet<>();
    private final List<Object> groupReports=new ArrayList<>();
    private static Map<String,Object> obj(Object... a){Map<String,Object> r=new LinkedHashMap<>();for(int i=0;i<a.length;i+=2)r.put((String)a[i],a[i+1]);return r;}
    private void require(boolean ok,String message){if(!ok)throw new IllegalStateException(message);}
    private static String hex(byte[] b){return HexFormat.of().formatHex(b);}
    private static String sha(byte[] b)throws Exception{return hex(MessageDigest.getInstance("SHA-256").digest(b));}
    private static String hx(long a){return String.format("0x%08x",a);}
    private Address at(long a){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(a);}
    private int offset(long a,int n){for(long[] l:loads)if(a>=l[0]&&a-l[0]+n<=l[2])return (int)(l[1]+a-l[0]);throw new IllegalStateException("Outside original load: "+hx(a));}
    private byte[] bytes(long a,int n)throws Exception{int o=offset(a,n);byte[] b=Arrays.copyOfRange(original,o,o+n),actual=new byte[n];int read=currentProgram.getMemory().getBytes(at(a),actual);if(read!=n)throw new IllegalStateException("Original memory short read at "+hx(a)+": "+read+" / "+n);int mismatch=Arrays.mismatch(b,actual);require(mismatch<0,"Original memory mismatch "+hx(a+Math.max(mismatch,0))+" file="+(mismatch<0?0:Byte.toUnsignedInt(b[mismatch]))+" memory="+(mismatch<0?0:Byte.toUnsignedInt(actual[mismatch])));return b;}
    private long word(long a)throws Exception{return Integer.toUnsignedLong(ByteBuffer.wrap(bytes(a,4)).order(ByteOrder.LITTLE_ENDIAN).getInt());}
    private List<Object> verifyAllMemory()throws Exception{
        List<Object> rows=new ArrayList<>();long matched=0;AddressSet covered=new AddressSet(),loaded=new AddressSet();
        for(long[] l:loads)loaded.add(at(l[0]),at(l[0]+l[2]-1));
        for(MemoryBlock block:currentProgram.getMemory().getBlocks()){
            Map<String,Object> row=obj("name",block.getName(),"start",block.getStart().toString(true),"end",block.getEnd().toString(true),"initialized",block.isInitialized());
            if(block.isInitialized()){
                int n=Math.toIntExact(block.getSize());byte[] b=new byte[n];require(block.getBytes(block.getStart(),b)==n,"Memory block short read");row.put("sha256",sha(b));
                if(block.getStart().getAddressSpace().equals(at(0).getAddressSpace())){
                    AddressSet intersection=new AddressSet(block.getStart(),block.getEnd()).intersect(loaded);
                    for(AddressRange range:intersection.getAddressRanges()){bytes(range.getMinAddress().getOffset(),Math.toIntExact(range.getLength()));matched+=range.getLength();}covered.add(intersection);
                }
            }rows.add(row);
        }
        require(matched>1000000,"Too little original-backed program memory verified");rows.add(obj("original_backed_bytes_verified",matched,"unmapped_or_uninitialized_PT_LOAD_bytes",ranges(loaded.subtract(covered)),"note","ELF segment padding is not necessarily imported as program memory; every initialized block is separately hashed."));return rows;
    }
    private void json(String name,Object data)throws Exception{try(Writer w=Files.newBufferedWriter(output.resolve(name),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)){gson.toJson(data,w);w.write('\n');}}
    private List<Object> ranges(AddressSetView body){List<Object> r=new ArrayList<>();for(AddressRange a:body.getAddressRanges())r.add(obj("start",a.getMinAddress().toString(true),"end_inclusive",a.getMaxAddress().toString(true),"bytes",a.getLength()));return r;}
    private Map<String,Object> describe(Function f){return obj("entry",f.getEntryPoint().toString(true),"name",f.getName(),"symbol_source",f.getSymbol().getSource().toString(),"signature",f.getSignature().toString(),"signature_source",f.getSignatureSource().toString(),"thunk",f.isThunk(),"body",ranges(f.getBody()));}
    private Map<Address,String> functions(){Map<Address,String> r=new TreeMap<>();FunctionIterator it=currentProgram.getFunctionManager().getFunctions(true);while(it.hasNext()){Function f=it.next();r.put(f.getEntryPoint(),compact.toJson(describe(f)));}return r;}
    private Map<String,Object> flow(Instruction i){List<String> targets=new ArrayList<>();for(Address a:i.getFlows())targets.add(a.toString(true));return obj("override",i.getFlowOverride().toString(),"type",i.getFlowType().toString(),"targets",targets,"fallthrough",i.getFallThrough()==null?null:i.getFallThrough().toString(true),"delay_slot_depth",i.getDelaySlotDepth());}
    private Map<Address,String> flows(){Map<Address,String> r=new TreeMap<>();InstructionIterator it=currentProgram.getListing().getInstructions(true);while(it.hasNext()){Instruction i=it.next();r.put(i.getAddress(),compact.toJson(flow(i)));}return r;}
    private List<Object> inventory(Map<Address,String> m){List<Object> r=new ArrayList<>();for(Map.Entry<Address,String> e:m.entrySet())r.add(obj("address",e.getKey().toString(true),"state",JsonParser.parseString(e.getValue())));return r;}
    private String fingerprint(Map<Address,String> m)throws Exception{MessageDigest d=MessageDigest.getInstance("SHA-256");for(Map.Entry<Address,String> e:m.entrySet())d.update((e.getKey().toString(true)+" "+e.getValue()+"\n").getBytes(StandardCharsets.UTF_8));return hex(d.digest());}
    private List<Object> delta(Map<Address,String> before,Map<Address,String> after,Set<Address> modified,Set<Address> added,String kind){
        List<Object> result=new ArrayList<>();Set<Address> all=new TreeSet<>(before.keySet());all.addAll(after.keySet());
        for(Address a:all){String b=before.get(a),c=after.get(a);if(Objects.equals(b,c))continue;require(c!=null,"Removed "+kind+" at "+a);require(b==null?added.contains(a):modified.contains(a),"Unexpected "+kind+" change at "+a);result.add(obj("address",a.toString(true),"before",b==null?null:JsonParser.parseString(b),"after",JsonParser.parseString(c)));}return result;
    }
    private List<Long> wrappers(long tail,long table)throws Exception{
        List<Long> r=new ArrayList<>();for(int slot=0;slot<25;slot++){long entry=word(table+slot*4);require(entry==tail+8+slot*24,"Unexpected fixed group table layout");long[] expected={0x27bdfff0L,0xffbf0000L,0xdfbf0000L,0x08000000L|(tail>>2),0x27bd0010L};for(int i=0;i<5;i++)require(word(entry+i*4)==expected[i],"Wrapper bytes changed");r.add(entry);}for(int slot=25;slot<28;slot++)require(word(table+slot*4)==0,"Table padding changed");return r;
    }
    private void validateGroup(long tail,long table)throws Exception{
        require(word(tail)==0x03e00008L&&word(tail+4)==0x0000102dL,"Shared tail bytes changed");
        FunctionManager fm=currentProgram.getFunctionManager();require(fm.getFunctionAt(at(tail))==null,"Tail already has entry in requested unmodified group");
        List<Long> entries=wrappers(tail,table);Function owner=fm.getFunctionAt(at(entries.get(0)));
        require(owner!=null&&owner.getBody().equals(new AddressSet(at(tail),at(tail+27))),"Owner boundary differs from reviewed snapshot");
        Set<Address> expectedRefs=new HashSet<>();for(int slot=0;slot<25;slot++){
            long e=entries.get(slot);if(slot>0)require(fm.getFunctionContaining(at(e))==null,"Wrapper entry already belongs to a function");
            for(int n=0;n<5;n++)require(currentProgram.getListing().getInstructionAt(at(e+n*4))!=null,"Wrapper instruction missing");
            Instruction jump=currentProgram.getListing().getInstructionAt(at(e+12));require(jump.getFlowOverride()==FlowOverride.NONE&&jump.getFlowType().isJump()&&jump.getFlowType().isUnConditional()&&jump.getDelaySlotDepth()==1,"Unexpected original jump flow");
            require(jump.getFlows().length==1&&jump.getFlows()[0].equals(at(tail)),"Unexpected original jump target");expectedRefs.add(at(e+12));
        }
        Set<Address> actualRefs=new HashSet<>();ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(at(tail));while(refs.hasNext()){Reference r=refs.next();if(r.getReferenceType().isFlow()){require(r.getReferenceType().isJump(),"Unexpected non-jump incoming flow");actualRefs.add(r.getFromAddress());}}
        require(actualRefs.equals(expectedRefs),"Incoming tail references differ from exact 25 wrappers");
        Instruction first=currentProgram.getListing().getInstructionAt(at(tail));require(first!=null&&first.getDelaySlotDepth()==1&&first.getFlowType().isTerminal(),"Tail is not a delayed return");
        Address fall=first.getFallFrom();if(fall!=null){Instruction previous=currentProgram.getListing().getInstructionContaining(fall);require(previous==null||!at(tail).equals(previous.getFallThrough()),"Unexpected fallthrough to shared tail");}
    }
    private Map<String,Object> oracle(long entry,long tail,int variant)throws Exception{
        EmulatorHelper emu=new EmulatorHelper(currentProgram);List<Object> faults=new ArrayList<>(),trace=new ArrayList<>();long sp=0x01f0f000L+variant*0x100,ret=0x01fffff0L-variant*16;
        try{
            emu.setMemoryFaultHandler(new MemoryFaultHandler(){public boolean unknownAddress(Address a,boolean w){faults.add(obj("address",a.toString(true),"write",w));return false;}public boolean uninitializedRead(Address a,int n,byte[] b,int o){faults.add(obj("address",a.toString(true),"bytes",n));return false;}});
            for(String reg:REGS)emu.writeRegister(reg+"_qw",BigInteger.ZERO);emu.writeRegister("pc_qw",BigInteger.ZERO);emu.writeRegister("v0",variant==0?0x12345678:0xffffffffL);emu.writeRegister("a0",0x01f04000L);emu.writeRegister("a1",0x01f05000L);emu.writeRegister("sp",sp);emu.writeRegister("ra",ret);emu.writeRegister(emu.getPCRegister(),entry);
            byte[] stack=new byte[64];Arrays.fill(stack,(byte)(0xa5+variant));emu.writeMemory(at(sp-32),stack);emu.enableMemoryWriteTracking(true);
            for(int step=0;step<12&&!emu.getExecutionAddress().equals(at(ret));step++){
                long pc=emu.getExecutionAddress().getOffset();require((pc>=entry&&pc<=entry+16)||(pc>=tail&&pc<=tail+4),"Oracle escaped proven wrapper and tail");
                Instruction ins=currentProgram.getListing().getInstructionAt(at(pc));require(ins!=null,"Oracle undefined instruction");bytes(pc,ins.getLength());boolean ok=emu.step(monitor);trace.add(obj("pc",hx(pc),"next_pc",emu.getExecutionAddress().toString(true),"ok",ok));require(ok,"Oracle failed: "+emu.getLastError());
            }
            require(faults.isEmpty()&&emu.getExecutionAddress().equals(at(ret))&&emu.readRegister("sp").longValue()==sp&&emu.readRegister("ra").longValue()==ret&&emu.readRegister("v0").longValue()==0,"Oracle return/SP/RA/value mismatch");
            ByteBuffer.wrap(stack).order(ByteOrder.LITTLE_ENDIAN).putLong(16,ret);byte[] after=emu.readMemory(at(sp-32),64);require(Arrays.equals(stack,after),"Unexpected oracle stack write");
            return obj("entry",hx(entry),"tail",hx(tail),"variant",variant,"status","passed","trace",trace,"sp",hx(sp),"return",hx(ret),"v0",0,"stack_sha256",sha(after),"faults",faults);
        }finally{emu.dispose();}
    }
    private List<Object> oracles(List<long[]> groups)throws Exception{List<Object> r=new ArrayList<>();for(long[] g:groups)for(long e:wrappers(g[0],g[1]))for(int v=0;v<2;v++)r.add(oracle(e,g[0],v));return r;}
    private void repair(long tail,long table)throws Exception{
        FunctionManager fm=currentProgram.getFunctionManager();List<Long> entries=wrappers(tail,table);Function owner=fm.getFunctionAt(at(entries.get(0)));Map<String,Object> report=obj("tail",hx(tail),"table",hx(table),"owner_before",describe(owner));
        String ownerName=owner.getName(),ownerSignature=owner.getSignature().toString();owner.setBody(new AddressSet(at(tail+8),at(tail+27)));allowedOwners.add(owner.getEntryPoint());
        Function helper=fm.createFunction("VM_SHARED_RETURN_ZERO_"+String.format("%08x",tail),at(tail),new AddressSet(at(tail),at(tail+7)),SourceType.USER_DEFINED);require(helper!=null,"Tail creation failed");allowedNew.add(at(tail));
        SharedReturnAnalysisCmd cmd=new SharedReturnAnalysisCmd(new AddressSet(at(tail),at(tail)),false,false);require(cmd.applyTo(currentProgram,monitor),"Official shared-return command failed");
        List<Object> wrapperReports=new ArrayList<>();for(int slot=0;slot<25;slot++){
            long e=entries.get(slot);Instruction jump=currentProgram.getListing().getInstructionAt(at(e+12));require(jump.getFlowOverride()==FlowOverride.CALL_RETURN&&jump.getDelaySlotDepth()==1&&jump.getFlows().length==1&&jump.getFlows()[0].equals(at(tail)),"Official tail flow mismatch");allowedFlows.add(at(e+12));
            AddressSetView body=CreateFunctionCmd.getFunctionBody(currentProgram,at(e),monitor);require(body.equals(new AddressSet(at(e),at(e+19))),"Inferred wrapper body not exact proof window");
            Function f;if(slot==0){owner.setBody(body);f=owner;}else{f=fm.createFunction("VM_SEED_"+String.format("%08x",e),at(e),body,SourceType.USER_DEFINED);allowedNew.add(at(e));}
            require(f!=null,"Wrapper function creation failed");wrapperReports.add(describe(f));
        }
        require(owner.getName().equals(ownerName)&&owner.getSignature().toString().equals(ownerSignature),"Owner identity changed");report.put("owner_after",describe(owner));report.put("tail_function",describe(helper));report.put("wrappers",wrapperReports);groupReports.add(report);
    }
    private List<Object> context()throws Exception{
        long[] ctor={0x3c0f0022L,0x25ef39f0L,0x03e00008L,0xac8f0000L};for(int n=0;n<4;n++)require(word(0x120230+n*4)==ctor[n],"Default-context constructor mismatch");
        FunctionManager fm=currentProgram.getFunctionManager();List<Object> r=new ArrayList<>();
        for(int slot=0;slot<CONTEXT.length;slot++){
            long e=CONTEXT[slot];require(word(0x2239f0+slot*4)==e,"Default context table mismatch");Function f=fm.getFunctionAt(at(e));boolean created=false;
            if(f==null){require(Set.of(0x120300L,0x120250L,0x1203e0L).contains(e),"Unexpected missing context entry "+hx(e));require(fm.getFunctionContaining(at(e))==null,"Context entry is inside an existing function");
                require(currentProgram.getListing().getDefinedDataContaining(at(e))==null,"Context entry is defined data");
                if(currentProgram.getListing().getInstructionAt(at(e))==null){AddressSet restrict=new AddressSet(at(0x100000),at(0x204b37));FunctionIterator all=fm.getFunctions(true);while(all.hasNext())restrict.delete(all.next().getBody());DisassembleCommand d=new DisassembleCommand(at(e),restrict,true);d.enableCodeAnalysis(false);require(d.applyTo(currentProgram,monitor),"Context disassembly failed");}
                AddressSetView body=CreateFunctionCmd.getFunctionBody(currentProgram,at(e),monitor);require(body.contains(at(e))&&body.getNumAddresses()>1&&body.getNumAddresses()<0x1000,"Invalid context inferred body");require(!fm.getFunctionsOverlapping(body).hasNext(),"Context inferred body overlaps existing function");
                for(long other:CONTEXT)if(other!=e)require(!body.contains(at(other)),"Context body swallows another table entry");
                for(AddressRange range:body.getAddressRanges())bytes(range.getMinAddress().getOffset(),Math.toIntExact(range.getLength()));
                f=fm.createFunction("VM_CONTEXT_SEED_"+String.format("%08x",e),at(e),body,SourceType.USER_DEFINED);require(f!=null,"Context creation failed");allowedNew.add(at(e));created=true;
            }
            r.add(obj("slot",slot,"pointer",hx(0x2239f0+slot*4),"created_evidence_guided",created,"function",describe(f)));
        }return r;
    }
    @Override public void run()throws Exception{
        String[] a=getScriptArgs();require(a.length==5,"Usage: <new-output> <original-ELF> <proof.json> <pilot|remaining|all> <project-root>");require(Set.of("pilot","remaining","all").contains(a[3]),"Unknown repair mode");
        require(currentProgram!=null&&currentProgram.getLanguageID().toString().equals("r5900:LE:32:default"),"Wrong language");original=Files.readAllBytes(Path.of(a[1]));require(SHA.equals(sha(original))&&SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()),"Wrong ELF/program SHA");root=Path.of(a[4]);
        ByteBuffer elf=ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);int ph=elf.getInt(28),count=Short.toUnsignedInt(elf.getShort(44));for(int i=0;i<count;i++){int p=ph+i*32;if(elf.getInt(p)==1)loads.add(new long[]{Integer.toUnsignedLong(elf.getInt(p+8)),Integer.toUnsignedLong(elf.getInt(p+4)),Integer.toUnsignedLong(elf.getInt(p+16))});}
        byte[] proof=Files.readAllBytes(Path.of(a[2]));JsonObject parsed=JsonParser.parseString(new String(proof,StandardCharsets.UTF_8)).getAsJsonObject();require(parsed.get("elf_sha256").getAsString().equals(SHA)&&parsed.getAsJsonArray("groups").size()==4,"Review proof identity mismatch");
        output=Path.of(a[0]);require(!Files.exists(output),"Output already exists");Files.createDirectories(output);byte[] harness;try(InputStream stream=getSourceFile().getInputStream()){harness=stream.readAllBytes();}Files.write(output.resolve("RepairKamaitachiSharedReturns.java"),harness);
        List<long[]> selected=new ArrayList<>();for(int i=0;i<4;i++)if(a[3].equals("all")||(a[3].equals("pilot")?i==0:i>0))selected.add(GROUPS[i]);
        Map<String,Object> result=obj("schema",1,"status","running","mode",a[3],"started_utc",Instant.now().toString(),"source_sha256",SHA,"script_sha256",sha(harness),"proof_sha256",sha(proof),"official_command_class_sha256",sha(SharedReturnAnalysisCmd.class.getResourceAsStream("SharedReturnAnalysisCmd.class").readAllBytes()),"official_command_options",obj("assume_contiguous",false,"allow_conditional",false),"original_bytes_written",false,"origin","evidence-guided-analysis-metadata-repair");
        int transaction=currentProgram.startTransaction("Repair proven shared returns and default context");boolean commit=false;Exception failure=null;
        try{
            List<Object> memoryBefore=verifyAllMemory();json("memory-before.json",memoryBefore);for(long[] g:selected)validateGroup(g[0],g[1]);Map<Address,String> beforeFunctions=functions(),beforeFlows=flows();json("functions-before.json",inventory(beforeFunctions));result.put("functions_before",beforeFunctions.size());result.put("flows_before_sha256",fingerprint(beforeFlows));
            List<Object> oracleBefore=oracles(selected);json("oracle-before.json",oracleBefore);
            for(long[] g:selected)repair(g[0],g[1]);if(!a[3].equals("pilot"))result.put("default_context",context());
            List<Object> oracleAfter=oracles(selected);json("oracle-after.json",oracleAfter);require(compact.toJson(oracleBefore).equals(compact.toJson(oracleAfter)),"Original instruction oracle changed after metadata repair");
            Map<Address,String> afterFunctions=functions(),afterFlows=flows();List<Object> functionDelta=delta(beforeFunctions,afterFunctions,allowedOwners,allowedNew,"function"),flowDelta=delta(beforeFlows,afterFlows,allowedFlows,Collections.emptySet(),"flow");
            require(flowDelta.size()==selected.size()*25,"Unexpected flow change count");require(afterFunctions.size()-beforeFunctions.size()==allowedNew.size(),"Function addition count mismatch");
            json("functions-after.json",inventory(afterFunctions));json("function-diff.json",functionDelta);json("flow-diff.json",flowDelta);result.put("functions_after",afterFunctions.size());result.put("functions_added",allowedNew.size());result.put("owners_changed",allowedOwners.size());result.put("flow_overrides_changed",flowDelta.size());result.put("flows_after_sha256",fingerprint(afterFlows));result.put("oracle_cases_before_and_after",oracleBefore.size());
            List<Object> memoryAfter=verifyAllMemory();json("memory-after.json",memoryAfter);require(compact.toJson(memoryBefore).equals(compact.toJson(memoryAfter)),"Program memory changed during metadata repair");require(SHA.equals(sha(Files.readAllBytes(Path.of(a[1])))),"Original ELF changed");commit=true;
        }catch(Exception ex){failure=ex;result.put("error",ex.toString());}
        finally{currentProgram.endTransaction(transaction,commit);result.put("status",commit?"repair_metadata_committed":"failed_rolled_back");result.put("database_mutation_committed",commit);result.put("groups",groupReports);result.put("completed_utc",Instant.now().toString());json("manifest.json",result);}
        if(failure!=null)throw failure;println("Shared-return repair committed: "+result.get("functions_added")+" functions, "+result.get("flow_overrides_changed")+" flow overrides");
    }
}
