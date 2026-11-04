// Export every function already identified in the retail EE database. Read-only.
// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.framework.Application;
import com.google.gson.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

public class ExportWholeEe extends GhidraScript {
    private static final String ELF="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final int SECTION_START=0x100000, SECTION_END=0x204b38, SECTION_OFFSET=0x1000;
    private static final int SHARD=64, TIMEOUT=30;
    private final Gson json=new GsonBuilder().disableHtmlEscaping().serializeNulls().create();
    private Path root;
    private byte[] elf;
    private String config;
    private String hex(long n){return String.format(Locale.ROOT,"%08x",n);}
    private String digest(Path p)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)));}
    private Map<String,Object> row(Object... fields){
        Map<String,Object> r=new LinkedHashMap<>();
        for(int i=0;i<fields.length;i+=2)r.put((String)fields[i],fields[i+1]);
        return r;
    }
    private void publish(Path dest,String text)throws Exception {
        Path temp=dest.resolveSibling(dest.getFileName()+".part");
        Files.writeString(temp,text);
        Files.move(temp,dest,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
    }
    private String stamp()throws Exception {
        // Include the reviewed database, extension and exporter itself in cache identity.
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        List<Path> paths=new ArrayList<>();
        try(var files=Files.walk(Path.of("local/ghidra-projects/kamaitachi-ee.rep/idata"))){
            files.filter(p->Files.isRegularFile(p)&&(p.toString().endsWith(".gbf")||p.toString().endsWith(".prp"))).forEach(paths::add);
        }
        if(paths.stream().noneMatch(p->p.toString().endsWith(".gbf")))throw new IOException("Main database identity missing");
        Path ext=Path.of("local/dependencies/ghidra-ee/ghidra_12.1.4_PUBLIC/Ghidra/Extensions/ghidra-emotionengine-reloaded");
        try(var files=Files.walk(ext)){
            files.filter(p->Files.isRegularFile(p)&&(p.toString().endsWith(".sla")||p.toString().endsWith(".cspec")||p.toString().endsWith(".pspec")||p.toString().endsWith(".ldefs"))).forEach(paths::add);
        }
        paths.add(Path.of("tools/ghidra/ExportWholeEe.java"));
        Collections.sort(paths);
        for(Path p:paths)md.update((p.toString()+":"+digest(p)+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        md.update((ELF+":"+Application.getApplicationVersion()).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(md.digest());
    }
    private String part(int n){return String.format(Locale.ROOT,"shard-%03d",n);}
    private void export(int n,List<Function> fs)throws Exception {
        String prefix=part(n);
        Path done=root.resolve(prefix+".done.json");
        if(Files.isRegularFile(done)){
            var meta=JsonParser.parseString(Files.readString(done)).getAsJsonObject();
            if(!config.equals(meta.get("identity").getAsString()))throw new IOException("Stale export: use a fresh output directory");
            for(var e:meta.getAsJsonObject("sha256").entrySet())
                if(!digest(root.resolve(e.getKey())).equals(e.getValue().getAsString()))throw new IOException("Altered shard "+e.getKey());
            return;
        }
        StringBuilder c=new StringBuilder(), asm=new StringBuilder(), idx=new StringBuilder();
        c.append("/* Ghidra inferred EE pseudocode. Original ELF SHA-256 ").append(ELF).append(". */\n");
        int cLine=2, asmLine=1;
        DecompInterface d=new DecompInterface();
        try{
            d.toggleCCode(true);d.toggleSyntaxTree(false);d.setSimplificationStyle("decompile");
            if(!d.openProgram(currentProgram))throw new IOException(d.getLastMessage());
            for(Function f:fs){
                monitor.checkCancelled();
                long address=f.getEntryPoint().getOffset();
                String id=hex(address);List<Object> ranges=new ArrayList<>(),calls=new ArrayList<>(),tails=new ArrayList<>();
                for(AddressRange r:f.getBody().getAddressRanges()){
                    long first=r.getMinAddress().getOffset(),end=r.getMaxAddress().getOffset()+1;
                    if(!r.getMinAddress().getAddressSpace().equals(f.getEntryPoint().getAddressSpace())||
                       first<SECTION_START||end>SECTION_END)throw new IOException("Noncanonical body "+id);
                    int offset=(int)(first-SECTION_START+SECTION_OFFSET);
                    byte[] raw=new byte[(int)(end-first)];
                    if(currentProgram.getMemory().getBytes(r.getMinAddress(),raw)!=raw.length ||
                       !Arrays.equals(elf,offset,offset+raw.length,raw,0,raw.length))throw new IOException("Original ELF mismatch "+id);
                    ranges.add(row("start",hex(first),"end_exclusive",hex(end),"file_offset",offset));
                }
                int aStart=asmLine;
                asm.append("\n; ").append(id).append(' ').append(f.getName()).append('\n');asmLine+=2;
                int insns=0,slots=0,unresolved=0;long instructionBytes=0;
                for(Instruction ins:currentProgram.getListing().getInstructions(f.getBody(),true)){
                    long pc=ins.getAddress().getOffset();
                    boolean delayed=ins.isInDelaySlot();
                    asm.append(hex(pc)).append(' ').append(HexFormat.of().formatHex(ins.getBytes()))
                       .append(delayed?" [delay] ":"         ").append(ins.toString()).append('\n');
                    ++asmLine;++insns;instructionBytes+=ins.getLength();if(delayed)++slots;
                    var flow=ins.getFlowType();
                    if(!flow.isCall() && !flow.isJump())continue;
                    List<String> targets=new ArrayList<>();
                    for(Reference ref:ins.getReferencesFrom()){
                        var type=ref.getReferenceType();
                        if(flow.isCall()?type.isCall():type.isJump()){
                            Address target=ref.getToAddress();
                            if(flow.isCall() || (!f.getBody().contains(target)&&currentProgram.getFunctionManager().getFunctionAt(target)!=null))
                                targets.add(target.toString(true));
                        }
                    }
                    if(flow.isCall()||!targets.isEmpty()||flow.isComputed()){
                        var r=row("pc",hex(pc),"flow",flow.getName(),"targets",targets,"delay_slots",ins.getDelaySlotDepth());
                        if(flow.isCall()){calls.add(r);if(targets.isEmpty())++unresolved;}else tails.add(r);
                    }
                }
                String code="",warning="",status;
                try {
                    DecompileResults result=d.decompileFunction(f,TIMEOUT,monitor);
                    if(result==null){status="failed";warning=d.getLastMessage();}
                    else{
                        warning=Objects.toString(result.getErrorMessage(),"");
                        var out=result.getDecompiledFunction();
                        if(result.decompileCompleted() && out!=null && out.getC()!=null && !out.getC().isBlank()){
                            code=out.getC().replace("\r","").stripTrailing()+"\n";status="c_emitted";
                        }else status=result.isTimedOut()?"timeout":"failed";
                    }
                }catch(RuntimeException e){status="failed";warning=e.toString();}
                if(!status.equals("c_emitted") && warning.isBlank())warning="Decompiler did not return a completed nonempty function body";
                int cStart=cLine;
                String header="\n/* "+id+" "+f.getName().replace("*/","* /")+" | "+status+" */\n";
                c.append(header).append(code);cLine+=2+(int)code.chars().filter(ch->ch=='\n').count();
                idx.append(json.toJson(row("entry",id,"name",f.getName(),"status",status,"diagnostic",warning,
                    "ranges",ranges,"body_bytes",f.getBody().getNumAddresses(),"instruction_count",insns,"instruction_bytes",instructionBytes,
                    "delay_slots_in_body",slots,"thunk",f.isThunk(),"calls",calls,"unresolved_call_sites",unresolved,
                    "jump_candidates",tails,"c",prefix+".c","c_line",cStart+1,"asm",prefix+".asm","asm_line",aStart+1))).append('\n');
            }
        }finally{d.dispose();}
        Map<String,String> sums=new LinkedHashMap<>();
        for(var e:Map.of(".c",c,".asm",asm,".jsonl",idx).entrySet()){
            Path p=root.resolve(prefix+e.getKey());publish(p,e.getValue().toString());sums.put(p.getFileName().toString(),digest(p));
        }
        publish(done,json.toJson(row("identity",config,"function_count",fs.size(),"first",hex(fs.get(0).getEntryPoint().getOffset()),"sha256",sums)));
    }
    public void run()throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2)throw new IllegalArgumentException("<output> <ELF>");
        root=Path.of(args[0]);Path input=Path.of(args[1]);
        elf=Files.readAllBytes(input);
        if(!ELF.equals(digest(input))||!ELF.equalsIgnoreCase(currentProgram.getExecutableSHA256())||
           !"r5900:LE:32:default".equals(currentProgram.getLanguageID().toString()))throw new IOException("Unexpected EE image");
        var block=currentProgram.getMemory().getBlock(".text");
        if(block==null || block.getStart().getOffset()!=SECTION_START|| block.getEnd().getOffset()!=SECTION_END-1)
            throw new IOException("Program text range changed");
        List<Function> fs=new ArrayList<>();
        for(Function f:currentProgram.getFunctionManager().getFunctions(true)){
            if(f.isExternal()||!block.contains(f.getEntryPoint()))throw new IOException("Unexpected function outside retail .text: "+f.getEntryPoint());
            fs.add(f);
        }
        Files.createDirectories(root);config=stamp();
        var run=row("artifact_sha256",ELF,"identity",config,"language",currentProgram.getLanguageID().toString(),
            "ghidra",Application.getApplicationVersion(),"function_count",fs.size(),"shard_size",SHARD,
            "text_start",hex(SECTION_START),"text_end_exclusive",hex(SECTION_END),"text_file_offset",SECTION_OFFSET);
        Path meta=root.resolve("source.json");
        String schema=json.toJson(run);
        if(Files.isRegularFile(meta)&&!schema.equals(Files.readString(meta)))throw new IOException("Output belongs to another database or exporter");
        publish(meta,schema);
        ExecutorService pool=Executors.newFixedThreadPool(4);
        CompletionService<Void> jobs=new ExecutorCompletionService<>(pool);
        int n=(fs.size()+SHARD-1)/SHARD;
        try{
            for(int i=0;i<n;++i){
                final int index=i;
                jobs.submit(()->{export(index,fs.subList(index*SHARD,Math.min((index+1)*SHARD,fs.size())));return null;});
            }
            for(int i=0;i<n;++i){
                jobs.take().get();
                if((i+1)%10==0||i+1==n)println("EE shards committed "+(i+1)+"/"+n);
            }
        }finally{pool.shutdownNow();pool.awaitTermination(TIMEOUT+10,TimeUnit.SECONDS);}
        if(!config.equals(stamp())||!ELF.equals(digest(input)))throw new IOException("Inputs changed during analysis");
        println("All function shards completed. Run tools/index_decompiled_ee.py to verify and index.");
    }
}
