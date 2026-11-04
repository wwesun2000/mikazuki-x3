// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import java.nio.file.*;
import com.google.gson.*;
import ghidra.program.model.address.AddressSet;
public class ExportScreenCallbacks extends GhidraScript {
    public void run() throws Exception {
        if(!currentProgram.getExecutableSHA256().equalsIgnoreCase("50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160"))
            throw new IllegalStateException("Wrong ELF");
        int[][] targets={{0x18ab10,0x179c40,0x18ad18},{0x18ab20,0x179c48,0x18aef8},{0x18ab30,0x179c58,0x18b028},
                         {0x18b078,0x179c40,0x18b290},{0x18b088,0x179c48,0x18b408},{0x18b098,0x179c58,0x18b580},
                         {0x1939c8,0x179c40,0x193bf0},{0x1939d8,0x179c48,0x193cb8},{0x1939e8,0x179c58,0x1944a8},
                         {0x18ef74,0x179c40,0x18f230},{0x18ef84,0x179c48,0x18f3e8},{0x18ef94,0x179c58,0x18f718}};
        for(int[] c:targets){
            if(getInt(toAddr(c[0]))!=(0x0c000000|(c[1]>>2)) ||
               getInt(toAddr(c[0]+4))!=(0x24a50000|(c[2]&65535)))
                throw new IllegalStateException("Unbound screen task callback");
            var addr=toAddr(c[2]);
            if(getFunctionAt(addr)==null){
                if(getFunctionContaining(addr)!=null)throw new IllegalStateException("Overlapping callback");
                disassemble(addr);
                if(createFunction(addr,null)==null)throw new IllegalStateException("Cannot define screen task callback");
            }
        }
        var request=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[2]))).getAsJsonObject();
        for(var value:request.getAsJsonArray("anchors")){
            var row=value.getAsJsonObject();
            if(row.has("direct_call_pc")){
                int entry=Integer.parseUnsignedInt(row.get("address").getAsString(),16);
                int pc=Integer.parseUnsignedInt(row.get("direct_call_pc").getAsString(),16);
                if(getInt(toAddr(pc))!=(0x0c000000|(entry>>2)))throw new IllegalStateException("Invalid direct effect call");
                var at=toAddr(entry);
                if(getFunctionAt(at)==null){
                    if(getFunctionContaining(at)!=null)throw new IllegalStateException("Overlapping direct effect call");
                    disassemble(at);
                    if(createFunction(at,null)==null)throw new IllegalStateException("Cannot define direct effect call");
                }
            }
            if(row.has("factory_table_index") || row.has("entry_jump_pc")){
                int entry=Integer.parseUnsignedInt(row.get("address").getAsString(),16);
                if(row.has("factory_table_index") && getInt(toAddr(0x205640+8*row.get("factory_table_index").getAsInt()))!=entry)
                    throw new IllegalStateException("Unbound original effect factory");
                if(row.has("entry_jump_pc") && getInt(toAddr(Integer.parseUnsignedInt(row.get("entry_jump_pc").getAsString(),16)))!=(0x08000000|(entry>>2)))
                    throw new IllegalStateException("Unbound original factory tail jump");
                var entryAddr=toAddr(entry);
                if(getFunctionAt(entryAddr)==null){
                    var owner=getFunctionContaining(entryAddr);
                    if(owner!=null){
                        // Ghidra followed the wrapper's tail jump into this shared body.
                        // Split the verified disjoint range only in this read-only session.
                        var shared=new AddressSet(toAddr(0x181a20),toAddr(0x181bc3));
                        if(entry!=0x181a20 || !owner.getEntryPoint().equals(toAddr(0x1819d0)) ||
                           !owner.getBody().contains(shared) || getInt(toAddr(0x1819ec))!=(0x08000000|(entry>>2)) ||
                           getInt(toAddr(0x181bbc))!=0x1000ffe0 || getInt(toAddr(0x181bc0))!=0x0260102d)
                            throw new IllegalStateException("Overlapping factory entry "+entryAddr);
                        owner.setBody(owner.getBody().subtract(shared));
                    }
                    disassemble(entryAddr);
                    if(createFunction(entryAddr,null)==null)throw new IllegalStateException("Cannot define original factory");
                }
            }
            if(!row.has("registration_pc"))continue;
            int pc=Integer.parseUnsignedInt(row.get("registration_pc").getAsString(),16);
            int callee=Integer.parseUnsignedInt(row.get("registration_callee").getAsString(),16);
            int target=Integer.parseUnsignedInt(row.get("address").getAsString(),16);
            int luiPc=Integer.parseUnsignedInt(row.get("lui_pc").getAsString(),16);
            int lui=Integer.parseUnsignedInt(row.get("lui_word").getAsString(),16);
            boolean tail=row.has("tail_registration") && row.get("tail_registration").getAsBoolean();
            int lowPc=tail?Integer.parseUnsignedInt(row.get("low_pc").getAsString(),16):pc+4;
            if(getInt(toAddr(pc))!=((tail?0x08000000:0x0c000000)|(callee>>2)) || getInt(toAddr(luiPc))!=lui ||
               getInt(toAddr(lowPc))!=(0x24a50000|(target&65535)) ||
               ((lui&65535)<<16)+(short)(target&65535)!=target)
                throw new IllegalStateException("Unbound additional screen callback");
            var addr=toAddr(target);
            if(getFunctionAt(addr)==null){
                if(getFunctionContaining(addr)!=null)throw new IllegalStateException("Overlapping additional callback");
                disassemble(addr);
                if(createFunction(addr,null)==null)throw new IllegalStateException("Cannot define additional callback");
            }
        }
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
