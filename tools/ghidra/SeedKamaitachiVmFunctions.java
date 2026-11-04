// Seed function metadata from the verified VM constructor/vtable chains.
// This is evidence-guided analyst input, not automatic function discovery.
// @category Kamaitachi.Evidence
// @author Codex

import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

public class SeedKamaitachiVmFunctions extends GhidraScript {
    private static final String ELF_SHA="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final String MAP_SHA="8063a89ae6b9bc4c158ee8e51bf5f85e77b6d6e47cce280d326cc0ee1aa2104f";
    private static final String LANGUAGE="r5900:LE:32:default";
    private final Gson gson=new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create();
    private byte[] original;
    private ByteBuffer elf;
    private AddressSpace space;
    private final List<long[]> loads=new ArrayList<>();
    private final AddressSet executable=new AddressSet();
    private final AddressSet protectedBodies=new AddressSet();
    private final AddressSet allSeedEntries=new AddressSet();
    private final List<Map<String,Object>> outcomes=new ArrayList<>();
    private final Map<Address,String> existingBodies=new LinkedHashMap<>();
    private final Map<String,JsonObject> sourceClasses=new HashMap<>();
    private final Map<String,Integer> counts=new TreeMap<>();
    private Path output;

    private static Map<String,Object> obj(Object... values) {
        Map<String,Object> result=new LinkedHashMap<>();
        for(int i=0;i<values.length;i+=2) result.put((String)values[i],values[i+1]);
        return result;
    }
    private static String sha(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static long number(String value) { return Long.parseUnsignedLong(value.replaceFirst("^0x", ""),16); }
    private static String hx(long value) { return String.format("0x%08x",value); }
    private long u32(int at) { return Integer.toUnsignedLong(elf.getInt(at)); }
    private int u16(int at) { return Short.toUnsignedInt(elf.getShort(at)); }
    private Address address(long value) { return space.getAddress(value); }
    private void require(boolean condition,String message) { if(!condition) throw new IllegalArgumentException(message); }
    private void bound(long off,long size) { require(off>=0 && size>=0 && off<=original.length && size<=original.length-off,"ELF range outside original bytes"); }
    private int fileOffset(long va,long length) {
        Integer result=null;
        for(long[] load:loads) if(va>=load[0] && va-load[0]<=load[2] && length<=load[2]-(va-load[0])) {
            require(result==null,"Ambiguous ELF mapping"); result=(int)(load[1]+va-load[0]);
        }
        require(result!=null,"No canonical file mapping at "+hx(va)); return result;
    }
    private byte[] verifyMemory(long va,int length) throws Exception {
        int off=fileOffset(va,length); bound(off,length);
        byte[] expected=Arrays.copyOfRange(original,off,off+length), observed=new byte[length];
        int read=currentProgram.getMemory().getBytes(address(va),observed);
        require(read==length && Arrays.equals(expected,observed),"Current memory differs from original ELF at "+hx(va));
        return expected;
    }
    private void verifyProof(JsonObject proof,boolean code) throws Exception {
        long va=number(proof.get("address").getAsString()); int size=proof.get("bytes").getAsInt();
        require(size>=1 && size<=112,"Unexpected proof extent");
        require(fileOffset(va,size)==proof.get("file_offset").getAsInt(),"Proof file offset mismatch");
        require(HexFormat.of().formatHex(verifyMemory(va,size)).equals(proof.get("raw_hex").getAsString()),"Proof bytes mismatch");
        if(code) require(executable.contains(address(va),address(va+size-1)),"Proof outside executable ELF section");
    }
    private void parseElf() {
        require(original.length>=52 && original[0]==0x7f && original[1]=='E' && original[2]=='L' && original[3]=='F' && original[4]==1 && original[5]==1,"ELF32 LE required");
        elf=ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);
        require(u16(16)==2 && u16(18)==8 && u32(36)==0x20920001L,"Unexpected R5900 header");
        require(u16(42)==32 && u16(46)==40,"Unexpected ELF table entry sizes");
        long phoff=u32(28),shoff=u32(32);
        for(int i=0;i<u16(44);i++) {
            long pos=phoff+i*32L; bound(pos,32); int p=(int)pos;
            if(u32(p)==1) { bound(u32(p+4),u32(p+16)); loads.add(new long[]{u32(p+8),u32(p+4),u32(p+16)}); }
        }
        for(int i=0;i<u16(48);i++) {
            long pos=shoff+i*40L; bound(pos,40); int p=(int)pos;
            long type=u32(p+4),flags=u32(p+8),va=u32(p+12),size=u32(p+20);
            if(type!=8 && (flags&6)==6 && size>0) { bound(u32(p+16),size); fileOffset(va,size); executable.add(address(va),address(va+size-1)); }
        }
    }
    private void verifyClass(JsonObject item) throws Exception {
        long factory=number(item.get("factory_case").getAsString()),ctor=number(item.get("constructor").getAsString()),vt=number(item.get("vtable_address").getAsString());
        ByteBuffer f=ByteBuffer.wrap(verifyMemory(factory,20)).order(ByteOrder.LITTLE_ENDIAN);
        long first=Integer.toUnsignedLong(f.getInt(0)),allocation=Integer.toUnsignedLong(f.getInt(4)),save=Integer.toUnsignedLong(f.getInt(8)),call=Integer.toUnsignedLong(f.getInt(12)),arg=Integer.toUnsignedLong(f.getInt(16));
        require(first==0x0c043eb4L && (allocation&0xffff0000L)==0x24040000L && save==0x0040802dL && (call>>>26)==3 && arg==0x0040202dL && (((factory+16)&0xf0000000L)|((call&0x03ffffffL)<<2))==ctor,"Factory/constructor chain mismatch");
        ByteBuffer c=ByteBuffer.wrap(verifyMemory(ctor,16)).order(ByteOrder.LITTLE_ENDIAN);
        long a=Integer.toUnsignedLong(c.getInt(0)),b=Integer.toUnsignedLong(c.getInt(4));
        require((a&0xffff0000L)==0x3c0f0000L && (b&0xffff0000L)==0x25ef0000L && c.getInt(8)==0x03e00008 && c.getInt(12)==0xac8f0000 && ((a&0xffff)<<16)+(short)(b&0xffff)==vt,"Constructor/vtable chain mismatch");
        ByteBuffer table=ByteBuffer.wrap(verifyMemory(vt,112)).order(ByteOrder.LITTLE_ENDIAN);
        JsonArray entries=item.getAsJsonArray("vtable_entries"); require(entries.size()==28,"Unexpected vtable size");
        for(int slot=0;slot<28;slot++) {
            JsonObject entry=entries.get(slot).getAsJsonObject(); long target=Integer.toUnsignedLong(table.getInt(slot*4));
            require(entry.get("slot").getAsInt()==slot && number(entry.get("target").getAsString())==target && number(entry.get("address").getAsString())==vt+slot*4,"Source vtable record mismatch");
            if(slot>=25) require(target==0,"Nonzero table padding");
            else require((target&3)==0 && executable.contains(address(target),address(target+15)),"Vtable target is not aligned executable code");
        }
    }
    private List<Object> ranges(AddressSetView body) {
        List<Object> result=new ArrayList<>();
        for(AddressRange range:body.getAddressRanges()) result.add(obj("start",range.getMinAddress().toString(true),"end_inclusive",range.getMaxAddress().toString(true),"bytes",range.getLength()));
        return result;
    }
    private String functionIdentity(Function f) { return f.getName()+"|"+f.getSignature().toString()+"|"+gson.toJson(ranges(f.getBody())); }
    private void verifyBody(AddressSetView body) throws Exception {
        require(!body.isEmpty() && new AddressSet(body).subtract(executable).isEmpty(),"Inferred body is outside canonical executable sections");
        for(AddressRange range:body.getAddressRanges()) {
            long start=range.getMinAddress().getOffset(),remaining=range.getLength();
            while(remaining>0) { int count=(int)Math.min(65536,remaining); verifyMemory(start,count); start+=count; remaining-=count; }
        }
    }
    private void outcome(Map<String,Object> row,String status) { row.put("status",status); counts.merge(status,1,Integer::sum); outcomes.add(row); }
    private void seed(JsonObject candidate,boolean apply) throws Exception {
        monitor.checkCancelled();
        JsonObject entryProof=candidate.getAsJsonObject("entry"); long va=number(entryProof.get("address").getAsString()); Address entry=address(va);
        Map<String,Object> row=obj("entry",hx(va),"class_id",candidate.get("class_id").getAsString(),"slot",candidate.get("slot").getAsInt(),"pointer_address",candidate.get("pointer_address").getAsString(),"origin","evidence-guided-vtable-pointer-not-automatic-discovery");
        FunctionManager manager=currentProgram.getFunctionManager(); Function exact=manager.getFunctionAt(entry);
        if(exact!=null) { row.put("existing_name",exact.getName()); outcome(row,"existing_function_unchanged"); return; }
        Function containing=manager.getFunctionContaining(entry);
        if(containing!=null) { row.put("containing_entry",containing.getEntryPoint().toString(true)); outcome(row,"conflict_containing_function"); return; }
        Listing listing=currentProgram.getListing();
        Data data=listing.getDefinedDataContaining(entry);
        if(data!=null) { row.put("data_address",data.getAddress().toString(true)); outcome(row,"conflict_defined_data"); return; }
        Instruction interior=listing.getInstructionContaining(entry);
        if(interior!=null && !interior.getAddress().equals(entry)) { row.put("instruction_address",interior.getAddress().toString(true)); outcome(row,"conflict_instruction_interior"); return; }
        boolean needDisassembly=listing.getInstructionAt(entry)==null; row.put("needed_disassembly",needDisassembly);
        if(!apply) { outcome(row,"reviewed_unclaimed_candidate"); return; }
        if(needDisassembly) {
            DisassembleCommand command=new DisassembleCommand(entry,new AddressSet(executable).subtract(protectedBodies),true);
            command.enableCodeAnalysis(false);
            boolean ok=command.applyTo(currentProgram,monitor);
            row.put("disassembled_bytes",command.getDisassembledAddressSet()==null?0:command.getDisassembledAddressSet().getNumAddresses());
            if(!ok || listing.getInstructionAt(entry)==null) { row.put("diagnostic",command.getStatusMsg()); outcome(row,"disassembly_failed"); return; }
        }
        AddressSetView body=CreateFunctionCmd.getFunctionBody(currentProgram,entry,monitor);
        if(body==null || body.isEmpty()) { outcome(row,"empty_inferred_body"); return; }
        if(body.intersects(protectedBodies)) { row.put("inferred_body",ranges(body)); outcome(row,"conflict_body_overlaps_function"); return; }
        AddressSet otherEntries=new AddressSet(body).intersect(allSeedEntries); otherEntries.delete(entry,entry);
        if(!otherEntries.isEmpty()) { row.put("other_seed_entries",ranges(otherEntries)); outcome(row,"conflict_body_contains_other_seed_entry"); return; }
        verifyBody(body);
        Function created=manager.createFunction("VM_SEED_"+String.format("%08x",va),entry,body,SourceType.USER_DEFINED);
        require(created!=null && created.getEntryPoint().equals(entry),"Function creation did not establish requested entry");
        protectedBodies.add(created.getBody()); row.put("name",created.getName()); row.put("body",ranges(created.getBody()));
        outcome(row,"created_evidence_guided");
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        require(args.length==5,"Usage: SeedKamaitachiVmFunctions.java <new-output-directory> <original-ELF> <candidates.json> <vm_handlers.json> <dry-run|apply>");
        boolean apply=args[4].equals("apply"); require(apply || args[4].equals("dry-run"),"Explicit dry-run or apply is required");
        require(currentProgram!=null && LANGUAGE.equals(currentProgram.getLanguageID().toString()),"Wrong program/language");
        original=Files.readAllBytes(Path.of(args[1])); require(ELF_SHA.equals(sha(original)) && ELF_SHA.equalsIgnoreCase(String.valueOf(currentProgram.getExecutableSHA256())),"ELF/program SHA-256 mismatch");
        space=currentProgram.getAddressFactory().getDefaultAddressSpace(); parseElf();
        byte[] mapRaw=Files.readAllBytes(Path.of(args[3])),candidateRaw=Files.readAllBytes(Path.of(args[2]));
        require(MAP_SHA.equals(sha(mapRaw)),"Reviewed VM source map changed");
        JsonObject source=JsonParser.parseString(new String(mapRaw,StandardCharsets.UTF_8)).getAsJsonObject();
        JsonObject manifest=JsonParser.parseString(new String(candidateRaw,StandardCharsets.UTF_8)).getAsJsonObject();
        require(ELF_SHA.equals(manifest.get("elf_sha256").getAsString()) && MAP_SHA.equals(manifest.get("vm_handlers_sha256").getAsString()) && LANGUAGE.equals(manifest.get("language_id").getAsString()),"Candidate manifest identity mismatch");
        for(JsonElement value:source.getAsJsonArray("handler_classes")) { JsonObject item=value.getAsJsonObject(); verifyClass(item); sourceClasses.put(item.get("id").getAsString(),item); }
        require(sourceClasses.size()==72,"Expected 72 source classes");
        List<JsonObject> candidates=new ArrayList<>(); Set<String> slots=new HashSet<>(); Set<Long> targets=new HashSet<>();
        for(JsonElement value:manifest.getAsJsonArray("candidates")) {
            JsonObject candidate=value.getAsJsonObject(),item=sourceClasses.get(candidate.get("class_id").getAsString()); int slot=candidate.get("slot").getAsInt();
            require(item!=null && slot>=0 && slot<25 && slots.add(item.get("id").getAsString()+":"+slot),"Unknown or duplicate class/slot");
            JsonObject expected=item.getAsJsonArray("vtable_entries").get(slot).getAsJsonObject(),proof=candidate.getAsJsonObject("entry");
            long target=number(expected.get("target").getAsString()),pointer=number(expected.get("address").getAsString());
            require(number(proof.get("address").getAsString())==target && targets.add(target) && proof.get("bytes").getAsInt()==16 && candidate.getAsJsonArray("opcodes").equals(item.getAsJsonArray("opcodes")),"Candidate does not match reviewed source slot");
            require(number(candidate.get("pointer_address").getAsString())==pointer && candidate.get("pointer_file_offset").getAsInt()==fileOffset(pointer,4) && candidate.get("pointer_raw_hex").getAsString().equals(HexFormat.of().formatHex(verifyMemory(pointer,4))),"Candidate pointer proof mismatch");
            verifyProof(proof,true); candidates.add(candidate); allSeedEntries.add(address(target));
        }
        require(candidates.size()==1800 && slots.size()==1800 && targets.size()==1800,"Expected exactly 1800 source-bound candidates");
        candidates.sort(Comparator.comparingLong(c -> number(c.getAsJsonObject("entry").get("address").getAsString())));
        FunctionIterator before=currentProgram.getFunctionManager().getFunctions(true);
        while(before.hasNext()) { Function f=before.next(); existingBodies.put(f.getEntryPoint(),functionIdentity(f)); protectedBodies.add(f.getBody()); }
        output=Path.of(args[0]).toAbsolutePath().normalize(); require(!Files.exists(output),"Output directory already exists"); Files.createDirectories(output);
        Map<String,Object> result=obj("schema",1,"mode",args[4],"started_utc",Instant.now().toString(),"status","running","source_sha256",ELF_SHA,"vm_handlers_sha256",MAP_SHA,"candidates_sha256",sha(candidateRaw),"language_id",LANGUAGE,"origin","evidence-guided-vtable-pointer-not-automatic-discovery","original_functions",existingBodies.size());
        int transaction=apply?currentProgram.startTransaction("Seed verified Kamaitachi VM table functions"):0; boolean commit=false; Exception failure=null;
        try {
            for(JsonObject candidate:candidates) seed(candidate,apply);
            for(Map.Entry<Address,String> old:existingBodies.entrySet()) { Function f=currentProgram.getFunctionManager().getFunctionAt(old.getKey()); require(f!=null && old.getValue().equals(functionIdentity(f)),"Preexisting function metadata changed"); }
            require(ELF_SHA.equals(sha(Files.readAllBytes(Path.of(args[1])))),"Original ELF changed during seeding");
            commit=true;
        } catch(Exception error) { failure=error; result.put("error",error.toString()); }
        finally {
            if(apply) currentProgram.endTransaction(transaction,commit);
            result.put("status",commit?(apply?"seed_metadata_committed":"dry_run_completed"):"failed_rolled_back");
            result.put("database_mutation_committed",apply && commit); result.put("completed_utc",Instant.now().toString()); result.put("counts",counts); result.put("outcomes",outcomes);
            result.put("limits",List.of("Function creation is evidence-guided, not an automatic-analysis discovery.","Original ELF bytes are never written; existing functions are not split, renamed or overwritten.","Disassembly enables no automatic code analysis. Unclaimed instructions may be decoded even when body creation later conflicts.","Conflict rows remain unresolved; inferred bodies and pointer provenance do not establish opcode semantics.","This script emits no decompiler output; export only selected slot15/slot1 functions and observed dependencies separately."));
            try(Writer writer=Files.newBufferedWriter(output.resolve("manifest.json"),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)) { gson.toJson(result,writer); writer.write('\n'); }
        }
        if(failure!=null) throw failure;
        println("VM function seeding "+result.get("status")+": "+gson.toJson(counts));
    }
}
