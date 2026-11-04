// Classify every byte of the original .text section using the existing read-only listing.
// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import com.google.gson.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class AuditWholeEeGaps extends GhidraScript {
    private static final int BASE=0x100000, END=0x204b38, OFFSET=0x1000;
    private final Gson json=new GsonBuilder().disableHtmlEscaping().create();
    private String hex(long a){return String.format(Locale.ROOT,"%08x",a);}
    private void mark(BitSet s,Address a,int length){int i=(int)a.getOffset()-BASE;s.set(i,i+length);}
    private void publish(Path p,String value)throws Exception {
        Path tmp=p.resolveSibling(p.getFileName()+".part");
        Files.writeString(tmp,value);Files.move(tmp,p,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
    }
    public void run()throws Exception {
        Path dir=Path.of(getScriptArgs()[0]);byte[] elf=Files.readAllBytes(Path.of(getScriptArgs()[1]));
        var source=JsonParser.parseString(Files.readString(dir.resolve("source.json"))).getAsJsonObject();
        String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(elf));
        if(!hash.equalsIgnoreCase(currentProgram.getExecutableSHA256())||!hash.equals(source.get("artifact_sha256").getAsString()))
            throw new IllegalStateException("ELF identity mismatch");
        var text=currentProgram.getMemory().getBlock(".text");
        if(!text.getStart().equals(toAddr(BASE))||!text.getEnd().equals(toAddr(END-1)))throw new IllegalStateException("Unexpected .text");
        byte[] image=new byte[END-BASE];
        if(text.getBytes(text.getStart(),image)!=image.length||!Arrays.equals(elf,OFFSET,OFFSET+image.length,image,0,image.length))
            throw new IllegalStateException("Some .text bytes differ from the original ELF");
        BitSet body=new BitSet(),code=new BitSet(),data=new BitSet();int count=0,orphanInstructions=0;
        for(Function f:currentProgram.getFunctionManager().getFunctions(true)){
            ++count;
            for(AddressRange r:f.getBody().getAddressRanges())mark(body,r.getMinAddress(),(int)r.getLength());
        }
        if(count!=source.get("function_count").getAsInt())throw new IllegalStateException("Function inventory changed");
        var set=new AddressSet(text.getStart(),text.getEnd());
        for(Data d:currentProgram.getListing().getDefinedData(set,true))mark(data,d.getAddress(),d.getLength());
        StringBuilder orphan=new StringBuilder("; canonical .text instructions without a known owning function, followed by incoming references where present\n");
        for(Instruction ins:currentProgram.getListing().getInstructions(set,true)){
            monitor.checkCancelled();
            Address pc=ins.getAddress();mark(code,pc,ins.getLength());
            if(body.get((int)pc.getOffset()-BASE))continue;
            ++orphanInstructions;
            orphan.append(hex(pc.getOffset())).append(' ').append(HexFormat.of().formatHex(ins.getBytes()))
                  .append(ins.isInDelaySlot()?" [delay] ":"         ").append(ins);
            for(Reference ref:currentProgram.getReferenceManager().getReferencesTo(pc))
                orphan.append(" | ").append(ref.getFromAddress().toString(true)).append(' ').append(ref.getReferenceType().getName());
            orphan.append('\n');
        }
        Map<String,Integer> counts=new TreeMap<>();StringBuilder gaps=new StringBuilder();
        gaps.append("start\tend_exclusive\telf_file_offset\tbytes\tlisting_kind\n");
        for(int i=0;i<image.length;){
            boolean b=body.get(i),c=code.get(i),d=data.get(i);
            int j=i+1;
            while(j<image.length&&b==body.get(j)&&c==code.get(j)&&d==data.get(j))++j;
            String kind=c?"instruction":(d?"defined_data":"undefined");
            counts.merge((b?"inside_":"outside_")+kind,j-i,Integer::sum);
            if(!b || !c)gaps.append(hex(BASE+i)).append('\t').append(hex(BASE+j)).append('\t').append(OFFSET+i).append('\t').append(j-i).append('\t').append((b?"inside_":"outside_")+kind).append('\n');
            i=j;
        }
        publish(dir.resolve("unowned.asm"),orphan.toString());
        publish(dir.resolve("gaps.tsv"),gaps.toString());
        publish(dir.resolve("coverage.json"),json.toJson(Map.of("identity",source.get("identity").getAsString(),
            "elf_sha256",hash,"text_bytes",image.length,"known_body_union",body.cardinality(),"instruction_bytes",code.cardinality(),
            "unowned_instructions",orphanInstructions,"byte_classification",counts)));
        println("Coverage audit complete: "+counts);
    }
}
