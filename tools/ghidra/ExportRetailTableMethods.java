// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import com.google.gson.JsonParser;
import java.nio.file.*;

public class ExportRetailTableMethods extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        var manifest=JsonParser.parseString(Files.readString(Paths.get(args[2]))).getAsJsonObject();
        if(!currentProgram.getExecutableSHA256().equalsIgnoreCase(manifest.get("elf_sha256").getAsString()))
            throw new IllegalStateException("Wrong retail executable");
        for(var item:manifest.getAsJsonArray("anchors")){
            var row=item.getAsJsonObject();
            var entry=toAddr(Long.parseLong(row.get("address").getAsString(),16));
            boolean tail=row.has("tail_jump");
            var site=toAddr(Long.parseLong(row.get(tail?"tail_jump":"vtable_word").getAsString(),16));
            long expected=tail?0x08000000 | (entry.getOffset()>>2):entry.getOffset();
            if(getInt(site)!=expected)throw new IllegalStateException("Wrong callback target at "+site);
            if(getFunctionAt(entry)==null && (getFunctionContaining(entry)!=null ||
               (getInstructionAt(entry)==null && !disassemble(entry)) || createFunction(entry,"FUN_"+entry)==null))
                throw new IllegalStateException("Cannot define original virtual method "+entry);
        }
        runScript("ExportKamaitachiEvidence.java",args);
    }
}
