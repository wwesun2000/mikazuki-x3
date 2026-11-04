// Export existing R5900 analysis without creating functions or modifying bytes.
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
import ghidra.app.decompiler.*;
import ghidra.framework.Application;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;

public class ExportKamaitachiEvidence extends GhidraScript {
    private static final String EXPECTED_SHA = "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final String LANGUAGE = "r5900:LE:32:default";
    private final Gson gson = new GsonBuilder().setPrettyPrinting().serializeNulls().disableHtmlEscaping().create();
    private final Gson compact = new GsonBuilder().serializeNulls().disableHtmlEscaping().create();
    private final List<Map<String,Object>> loads = new ArrayList<>();
    private final List<Map<String,Object>> sections = new ArrayList<>();
    private final List<Object> issues = new ArrayList<>();
    private final BitSet instructionFileBytes = new BitSet();
    private final BitSet functionFileBytes = new BitSet();
    private final BitSet executableSectionBytes = new BitSet();
    private byte[] original;
    private Path output;
    private int timeoutSeconds = 45;
    private long functions, references, callsites, unmappedInstructions, mismatchedInstructions;

    private static Map<String,Object> obj(Object... values) {
        Map<String,Object> result = new LinkedHashMap<>();
        for (int i=0;i<values.length;i+=2) result.put((String)values[i],values[i+1]);
        return result;
    }
    private static String hex(byte[] bytes) { return HexFormat.of().formatHex(bytes); }
    private static String sha(byte[] bytes) throws Exception { return hex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    private static String addr(Address address) { return address == null ? null : address.toString(true); }
    private static String csv(Object value) { return "\"" + String.valueOf(value == null ? "" : value).replace("\"", "\"\"") + "\""; }
    private void csvLine(Writer writer,Object... columns) throws IOException {
        for (int i=0;i<columns.length;i++) { if(i!=0) writer.write(','); writer.write(csv(columns[i])); }
        writer.write('\n');
    }
    private void json(String name,Object value) throws IOException {
        Path target=output.resolve(name);
        try(Writer writer=Files.newBufferedWriter(target,StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)) { gson.toJson(value,writer); writer.write('\n'); }
    }
    private long u32(ByteBuffer buffer,int offset) { return Integer.toUnsignedLong(buffer.getInt(offset)); }
    private int u16(ByteBuffer buffer,int offset) { return Short.toUnsignedInt(buffer.getShort(offset)); }
    private void bounded(long offset,long size) {
        if(offset<0 || size<0 || offset>original.length || size>original.length-offset) throw new IllegalArgumentException("ELF file range outside source");
    }
    private void parseElf() {
        if(original.length<52 || original[0]!=0x7f || original[1]!='E' || original[2]!='L' || original[3]!='F' || original[4]!=1 || original[5]!=1) throw new IllegalArgumentException("Expected ELF32 little-endian");
        ByteBuffer buffer=ByteBuffer.wrap(original).order(ByteOrder.LITTLE_ENDIAN);
        if(u16(buffer,18)!=8 || u16(buffer,42)!=32) throw new IllegalArgumentException("Expected MIPS ELF32 program headers");
        long phoff=u32(buffer,28);
        for(int i=0;i<u16(buffer,44);i++) {
            long position=phoff+i*32L; bounded(position,32); int p=(int)position;
            if(u32(buffer,p)!=1) continue;
            long off=u32(buffer,p+4), va=u32(buffer,p+8), size=u32(buffer,p+16), memsize=u32(buffer,p+20);
            bounded(off,size); if(size>memsize) throw new IllegalArgumentException("Invalid PT_LOAD extent");
            loads.add(obj("index",i,"file_offset",off,"virtual_address",va,"file_size",size,"memory_size",memsize,"flags",u32(buffer,p+24)));
        }
        long shoff=u32(buffer,32); int shsize=u16(buffer,46), shcount=u16(buffer,48);
        if(shcount>0 && shsize!=40) throw new IllegalArgumentException("Unexpected ELF32 section size");
        for(int i=0;i<shcount;i++) {
            long position=shoff+i*40L; bounded(position,40); int p=(int)position;
            long flags=u32(buffer,p+8), off=u32(buffer,p+16), size=u32(buffer,p+20), type=u32(buffer,p+4);
            if(type!=8) bounded(off,size);
            sections.add(obj("index",i,"type",type,"flags",flags,"virtual_address",u32(buffer,p+12),"file_offset",off,"size",size));
            if(type!=8 && (flags&6)==6) executableSectionBytes.set((int)off,(int)(off+size));
        }
    }
    // Only canonical PT_LOAD virtual addresses in the default space qualify.
    // Mirrors/overlays are deliberately not folded into RAM and not recounted.
    private Integer fileOffset(Address address,long length) {
        if(address==null || !address.getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace()) || length<0) return null;
        long va=address.getOffset(); Integer found=null;
        for(Map<String,Object> load:loads) {
            long start=(long)load.get("virtual_address"), size=(long)load.get("file_size");
            if(va>=start && va-start<=size && length<=size-(va-start)) {
                if(found!=null) return null;
                found=(int)((long)load.get("file_offset")+va-start);
            }
        }
        return found;
    }
    private Map<String,Object> bytesAt(Address address,int length) throws Exception {
        Map<String,Object> result=obj("address",addr(address),"length",length);
        Integer offset=fileOffset(address,length); result.put("canonical_elf_file_offset",offset);
        try {
            byte[] bytes=new byte[length]; int read=currentProgram.getMemory().getBytes(address,bytes);
            if(read!=length) throw new IOException("Short memory read: "+read+"/"+length);
            result.put("memory_bytes_status","read"); result.put("raw_hex",hex(bytes)); result.put("raw_sha256",sha(bytes));
            result.put("matches_original_elf",offset==null ? null : Arrays.equals(bytes,Arrays.copyOfRange(original,offset,offset+length)));
            if(offset!=null) result.put("original_elf_raw_hex",hex(Arrays.copyOfRange(original,offset,offset+length)));
        } catch(MemoryAccessException | IOException error) {
            result.put("memory_bytes_status","unreadable"); result.put("error",error.toString()); result.put("matches_original_elf",null);
        }
        return result;
    }
    private List<Object> ranges(AddressSetView set) {
        List<Object> result=new ArrayList<>();
        for(AddressRange range:set.getAddressRanges()) result.add(obj("min",addr(range.getMinAddress()),"max_inclusive",addr(range.getMaxAddress()),"length",range.getLength(),"canonical_elf_file_offset",fileOffset(range.getMinAddress(),range.getLength())));
        return result;
    }
    private void markFunctionCoverage(AddressSetView body) {
        for(AddressRange range:body.getAddressRanges()) {
            if(!range.getMinAddress().getAddressSpace().equals(currentProgram.getAddressFactory().getDefaultAddressSpace())) continue;
            long lo=range.getMinAddress().getOffset(), hi=range.getMaxAddress().getOffset()+1;
            for(Map<String,Object> load:loads) {
                long base=(long)load.get("virtual_address"), a=Math.max(lo,base), z=Math.min(hi,base+(long)load.get("file_size"));
                if(z>a) { int start=(int)((long)load.get("file_offset")+a-base); functionFileBytes.set(start,start+(int)(z-a)); }
            }
        }
    }
    private Map<String,Object> functionInfo(Function function) {
        return obj("entry",addr(function.getEntryPoint()),"name",function.getName(true),"symbol_source",function.getSymbol().getSource().toString(),
            "signature_source",function.getSignatureSource().toString(),"signature",function.getPrototypeString(true,true),
            "external",function.isExternal(),"thunk",function.isThunk(),"body_address_count",function.getBody().getNumAddresses(),
            "body_ranges",ranges(function.getBody()),"canonical_entry_file_offset",fileOffset(function.getEntryPoint(),1),
            "boundary_authority","existing Ghidra database; not created or changed by this exporter");
    }
    private void memorySummary() throws Exception {
        List<Object> blocks=new ArrayList<>();
        for(MemoryBlock block:currentProgram.getMemory().getBlocks()) {
            List<Object> sources=new ArrayList<>();
            for(MemoryBlockSourceInfo info:block.getSourceInfos()) {
                Map<String,Object> source=obj("min",addr(info.getMinAddress()),"max_inclusive",addr(info.getMaxAddress()),"length",info.getLength(),"description",info.getDescription(),"file_bytes_offset",info.getFileBytesOffset());
                if(info.getFileBytes().isPresent()) {
                    FileBytes bytes=info.getFileBytes().get(); source.put("file_bytes",obj("filename",bytes.getFilename(),"file_offset",bytes.getFileOffset(),"size",bytes.getSize()));
                } else source.put("file_bytes",null);
                source.put("mapped_range",info.getMappedRange().isPresent()?info.getMappedRange().get().toString():null); sources.add(source);
            }
            blocks.add(obj("name",block.getName(),"start",addr(block.getStart()),"end_inclusive",addr(block.getEnd()),"size",block.getSize(),"type",block.getType().toString(),
                "initialized",block.isInitialized(),"mapped",block.isMapped(),"overlay",block.isOverlay(),"read",block.isRead(),"write",block.isWrite(),"execute",block.isExecute(),
                "source_name",block.getSourceName(),"source_infos",sources,"canonical_elf_file_offset_for_entire_block",fileOffset(block.getStart(),block.getSize())));
        }
        json("memory.json",obj("blocks",blocks,"original_elf_pt_load",loads,"original_elf_sections",sections,
            "coverage_policy","Canonical default-space PT_LOAD file offsets only; overlays/mirrors and uninitialized RAM do not increase file-byte coverage."));
    }
    private void exportFunctions() throws Exception {
        try(Writer writer=Files.newBufferedWriter(output.resolve("functions.csv"),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)) {
            csvLine(writer,"entry","name","symbol_source","signature_source","external","thunk","body_address_count","canonical_entry_file_offset","body_ranges_json","signature");
            FunctionIterator iterator=currentProgram.getFunctionManager().getFunctions(true);
            while(iterator.hasNext()) {
                monitor.checkCancelled(); Function function=iterator.next(); Map<String,Object> row=functionInfo(function); functions++;
                csvLine(writer,row.get("entry"),row.get("name"),row.get("symbol_source"),row.get("signature_source"),row.get("external"),row.get("thunk"),row.get("body_address_count"),row.get("canonical_entry_file_offset"),compact.toJson(row.get("body_ranges")),row.get("signature"));
                markFunctionCoverage(function.getBody());
            }
            FunctionIterator external=currentProgram.getFunctionManager().getExternalFunctions();
            while(external.hasNext()) {
                monitor.checkCancelled(); Function function=external.next(); Map<String,Object> row=functionInfo(function); functions++;
                csvLine(writer,row.get("entry"),row.get("name"),row.get("symbol_source"),row.get("signature_source"),true,row.get("thunk"),row.get("body_address_count"),null,compact.toJson(row.get("body_ranges")),row.get("signature"));
            }
        }
    }
    private Map<String,Object> referenceInfo(Reference reference) {
        Function from=currentProgram.getFunctionManager().getFunctionContaining(reference.getFromAddress());
        Function to=currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
        return obj("from",addr(reference.getFromAddress()),"to",addr(reference.getToAddress()),"type",reference.getReferenceType().toString(),"source",reference.getSource().toString(),
            "operand_index",reference.getOperandIndex(),"primary",reference.isPrimary(),"call",reference.getReferenceType().isCall(),
            "from_function",from==null?null:addr(from.getEntryPoint()),"to_function_entry",to==null?null:addr(to.getEntryPoint()));
    }
    private void exportReferencesAndCalls() throws Exception {
        ReferenceManager manager=currentProgram.getReferenceManager();
        try(Writer writer=Files.newBufferedWriter(output.resolve("references.csv"),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)) {
            csvLine(writer,"from","to","type","source","operand_index","primary","call","from_function","to_function_entry");
            // 12.1.4's public Javadoc allows null, but this database backend
            // dereferences it. Export the explicit complete program memory set.
            AddressIterator iterator=manager.getReferenceSourceIterator(currentProgram.getMemory(),true);
            while(iterator.hasNext()) {
                monitor.checkCancelled();
                for(Reference reference:manager.getReferencesFrom(iterator.next())) {
                    Map<String,Object> row=referenceInfo(reference); references++;
                    csvLine(writer,row.get("from"),row.get("to"),row.get("type"),row.get("source"),row.get("operand_index"),row.get("primary"),row.get("call"),row.get("from_function"),row.get("to_function_entry"));
                }
            }
        }
        try(Writer writer=Files.newBufferedWriter(output.resolve("calls.jsonl"),StandardCharsets.UTF_8,StandardOpenOption.CREATE_NEW)) {
            InstructionIterator iterator=currentProgram.getListing().getInstructions(true);
            while(iterator.hasNext()) {
                monitor.checkCancelled(); Instruction instruction=iterator.next(); Map<String,Object> bytes=bytesAt(instruction.getAddress(),instruction.getLength());
                Integer offset=fileOffset(instruction.getAddress(),instruction.getLength());
                if(offset==null) unmappedInstructions++;
                else if(Boolean.TRUE.equals(bytes.get("matches_original_elf"))) instructionFileBytes.set(offset,offset+instruction.getLength());
                else mismatchedInstructions++;
                if(!instruction.getFlowType().isCall()) continue;
                List<Object> edges=new ArrayList<>();
                for(Reference reference:manager.getReferencesFrom(instruction.getAddress())) if(reference.getReferenceType().isCall()) edges.add(referenceInfo(reference));
                Function owner=currentProgram.getFunctionManager().getFunctionContaining(instruction.getAddress());
                Map<String,Object> row=obj("address",addr(instruction.getAddress()),"from_function",owner==null?null:addr(owner.getEntryPoint()),"disassembly",instruction.toString(),"flow_type",instruction.getFlowType().toString(),"computed",instruction.getFlowType().isComputed(),
                    "resolved_call_references",edges,"target_status",edges.isEmpty()?"unresolved":"database_references","delay_slot_depth",instruction.getDelaySlotDepth(),"bytes",bytes);
                compact.toJson(row,writer); writer.write('\n'); callsites++;
            }
        }
    }
    private Map<String,Object> listing(Function function) throws Exception {
        List<Object> units=new ArrayList<>(); long emitted=0, instructions=0, undefinedBytes=0, unimplementedPcode=0, useropPcode=0;
        if(function.getBody().getNumAddresses()>16*1024*1024) return obj("status","refused_oversized_body","complete",false,"limit_bytes",16*1024*1024,"body_bytes",function.getBody().getNumAddresses());
        for(AddressRange range:function.getBody().getAddressRanges()) {
            Address cursor=range.getMinAddress();
            while(cursor!=null && cursor.compareTo(range.getMaxAddress())<=0) {
                monitor.checkCancelled(); CodeUnit unit=currentProgram.getListing().getCodeUnitAt(cursor);
                int length=unit==null?1:unit.getLength(); long remaining=range.getMaxAddress().subtract(cursor)+1;
                boolean clipped=length>remaining; if(clipped) length=(int)remaining;
                Map<String,Object> row=bytesAt(cursor,length); emitted+=length;
                row.put("clipped_at_function_body_boundary",clipped);
                if(unit instanceof Instruction && !clipped) {
                    Instruction instruction=(Instruction)unit; instructions++;
                    row.put("kind","instruction"); row.put("disassembly",instruction.toString()); row.put("mnemonic",instruction.getMnemonicString());
                    row.put("flow_type",instruction.getFlowType().toString()); row.put("flow_override",instruction.getFlowOverride().toString()); row.put("fallthrough",addr(instruction.getFallThrough())); row.put("delay_slot_depth",instruction.getDelaySlotDepth());
                    List<Object> targets=new ArrayList<>(); if(instruction.getFlows()!=null) for(Address target:instruction.getFlows()) targets.add(addr(target)); row.put("flows",targets);
                    List<Object> pcode=new ArrayList<>();
                    try {
                        for(PcodeOp operation:instruction.getPcode()) {
                            pcode.add(operation.toString());
                            if(operation.getOpcode()==PcodeOp.UNIMPLEMENTED) unimplementedPcode++;
                            if(operation.getOpcode()==PcodeOp.CALLOTHER) useropPcode++;
                        }
                        row.put("pcode_status",pcode.isEmpty()?"empty_not_necessarily_invalid":"produced"); row.put("pcode",pcode);
                    } catch(Exception error) { row.put("pcode_status","error"); row.put("pcode_error",error.toString()); }
                    List<Object> refs=new ArrayList<>(); for(Reference reference:currentProgram.getReferenceManager().getReferencesFrom(cursor)) refs.add(referenceInfo(reference)); row.put("references",refs);
                } else if(unit instanceof Data && ((Data)unit).isDefined() && !clipped) {
                    row.put("kind","defined_data_in_function_body"); row.put("datatype",((Data)unit).getDataType().getPathName());
                } else { row.put("kind",clipped?"partial_codeunit_boundary":"undefined_bytes"); undefinedBytes+=length; }
                units.add(row); if(remaining==length) break; cursor=cursor.add(length);
            }
        }
        return obj("status","exported_existing_body","complete",emitted==function.getBody().getNumAddresses(),"body_bytes",function.getBody().getNumAddresses(),"emitted_bytes",emitted,"instruction_count",instructions,"undefined_or_partial_bytes",undefinedBytes,"unimplemented_pcode_operations",unimplementedPcode,"userop_pcode_operations",useropPcode,
            "semantic_limit","Complete here means every byte of the existing body is represented. UNIMPLEMENTED/CALLOTHER and successful C output do not prove full R5900 semantic recovery.","units",units);
    }
    private List<Object> selected(JsonArray anchors) throws Exception {
        List<Object> results=new ArrayList<>(), missing=new ArrayList<>(); DecompInterface decompiler=new DecompInterface();
        boolean opened=false;
        try {
            decompiler.toggleCCode(true); decompiler.toggleSyntaxTree(true); decompiler.setSimplificationStyle("decompile"); opened=decompiler.openProgram(currentProgram);
            if(!opened) issues.add(obj("kind","decompiler_open_failed","message",decompiler.getLastMessage()));
            for(JsonElement element:anchors) {
                monitor.checkCancelled(); JsonObject anchor=element.getAsJsonObject(); String requested=anchor.get("address").getAsString();
                Map<String,Object> result=obj("requested_anchor",gson.fromJson(anchor,Object.class)); Address entry=toAddr(requested);
                if(entry==null) { result.put("status","invalid_address"); results.add(result); continue; }
                result.put("requested_address",addr(entry)); Function function=currentProgram.getFunctionManager().getFunctionAt(entry);
                if(function==null) {
                    Function containing=currentProgram.getFunctionManager().getFunctionContaining(entry);
                    result.put("status","no_function_at_requested_entry"); result.put("containing_function",containing==null?null:functionInfo(containing));
                    result.put("entry_bytes",bytesAt(entry,16)); result.put("function_created",false); missing.add(result); results.add(result); continue;
                }
                result.put("status","existing_function"); result.put("function",functionInfo(function)); result.put("disassembly",listing(function));
                if(!opened) result.put("decompilation",obj("status","decompiler_open_failed","message",decompiler.getLastMessage()));
                else {
                    try {
                        DecompileResults decompiled=decompiler.decompileFunction(function,timeoutSeconds,monitor);
                        if(decompiled==null) result.put("decompilation",obj("status","null_result","complete",false));
                        else {
                            DecompiledFunction c=decompiled.getDecompiledFunction();
                            result.put("decompilation",obj("status",decompiled.isTimedOut()?"timeout":decompiled.isCancelled()?"cancelled":decompiled.decompileCompleted()&&c!=null?"completed":"failed",
                                "complete",decompiled.decompileCompleted()&&c!=null,"error_or_warning",decompiled.getErrorMessage(),"timeout_seconds",timeoutSeconds,
                                "signature",c==null?null:c.getSignature(),"c",c==null?null:c.getC(),"authority","Ghidra inferred pseudocode, not verified original source"));
                        }
                    } catch(Exception error) { result.put("decompilation",obj("status","exception","complete",false,"error",error.toString())); }
                    decompiler.flushCache();
                }
                String filename="functions/"+String.format("%08x",entry.getOffset())+".json"; json(filename,result);
                results.add(obj("requested_address",addr(entry),"file",filename,"status",result.get("status"),"decompilation_status",((Map<?,?>)result.get("decompilation")).get("status")));
                println("Exported "+addr(entry)+" "+function.getName());
            }
        } finally { decompiler.dispose(); }
        json("needs_function_creation.json",obj("automatic_creation_performed",false,"policy","Requests only. Independently validate entry and record creation evidence before running a separate mutation script.","anchors",missing));
        return results;
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length<3 || args.length>4) throw new IllegalArgumentException("Usage: ExportKamaitachiEvidence.java <new-output-directory> <original-ELF> <anchors.json> [decompile-timeout-seconds]");
        if(currentProgram==null) throw new IllegalStateException("No current program");
        if(!LANGUAGE.equals(currentProgram.getLanguageID().toString())) throw new IllegalStateException("Refuse wrong language: "+currentProgram.getLanguageID()+"; expected "+LANGUAGE);
        original=Files.readAllBytes(Path.of(args[1])); String digest=sha(original);
        if(!EXPECTED_SHA.equals(digest) || !EXPECTED_SHA.equalsIgnoreCase(String.valueOf(currentProgram.getExecutableSHA256()))) throw new IllegalStateException("Original ELF/current-program SHA mismatch");
        if(args.length==4) timeoutSeconds=Integer.parseInt(args[3]);
        if(timeoutSeconds<1 || timeoutSeconds>300) throw new IllegalArgumentException("Timeout must be1..300seconds");
        JsonObject anchorFile=JsonParser.parseString(Files.readString(Path.of(args[2]),StandardCharsets.UTF_8)).getAsJsonObject();
        if(!EXPECTED_SHA.equals(anchorFile.get("elf_sha256").getAsString()) || !LANGUAGE.equals(anchorFile.get("language_id").getAsString())) throw new IllegalArgumentException("Anchor identity mismatch");
        output=Path.of(args[0]).toAbsolutePath().normalize();
        if(Files.exists(output,LinkOption.NOFOLLOW_LINKS)) throw new IOException("Refuse existing output directory: "+output);
        Files.createDirectories(output.getParent()); Files.createDirectory(output); Files.createDirectory(output.resolve("functions"));
        Map<String,Object> manifest=obj("schema",1,"started_utc",Instant.now().toString(),"status","in_progress","program_name",currentProgram.getName(),"program_path",currentProgram.getDomainFile().getPathname(),
            "language_id",currentProgram.getLanguageID().toString(),"compiler_spec",currentProgram.getCompilerSpec().getCompilerSpecID().toString(),"ghidra_version",Application.getApplicationVersion(),
            "source_elf",Path.of(args[1]).toAbsolutePath().toString(),"source_sha256",digest,"source_size",original.length,"program_executable_path",currentProgram.getExecutablePath(),"program_executable_sha256",currentProgram.getExecutableSHA256(),
            "anchor_file_sha256",sha(Files.readAllBytes(Path.of(args[2]))),"mutations_performed",Collections.emptyList(),"issues",issues);
        manifest.put("reference_scope","All database references sourced from program memory, including mapped/overlay blocks. Non-memory source spaces are not enumerated.");
        json("started.json",manifest);
        try {
            parseElf(); memorySummary(); exportFunctions(); exportReferencesAndCalls(); manifest.put("selected",selected(anchorFile.getAsJsonArray("anchors")));
            BitSet definedExecutable=(BitSet)instructionFileBytes.clone(); definedExecutable.and(executableSectionBytes);
            manifest.put("counts",obj("database_functions_including_external",functions,"references",references,"call_instructions",callsites,
                "unique_original_file_bytes_in_existing_function_bodies",functionFileBytes.cardinality(),"unique_original_file_bytes_with_matching_instructions",instructionFileBytes.cardinality(),
                "original_alloc_executable_section_bytes",executableSectionBytes.cardinality(),"matching_instruction_bytes_in_alloc_executable_sections",definedExecutable.cardinality(),
                "instructions_outside_canonical_file_mapping",unmappedInstructions,"canonical_instructions_with_changed_or_unreadable_bytes",mismatchedInstructions));
            manifest.put("coverage_limit","Byte counts are deduplicated ELF file offsets, not proven code/behavior completeness. Function boundaries and references are current database analysis; indirect targets may remain unresolved. EE RAM mirrors and overlays never enlarge these counts.");
            manifest.put("status","export_completed");
        } catch(Exception error) { manifest.put("status",monitor.isCancelled()?"cancelled":"failed"); issues.add(obj("kind","export_exception","error",error.toString())); throw error; }
        finally { manifest.put("finished_utc",Instant.now().toString()); json("manifest.json",manifest); }
        println("Evidence export completed: "+output);
    }
}
