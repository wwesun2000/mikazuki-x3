// Execute a source-bounded prefix of the first command on native-constructed RAM.
// @category Kamaitachi.Evidence
import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.Address;

@SuppressWarnings("removal")
public class InspectColdFirstDispatch extends GhidraScript {
    private static final String ELF="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final Set<Long> PREFIX=Set.of(0x120308L,0x1133a8L,0x10d610L,0x10d5d8L,
        0x1133b0L,0x1203e0L,0x12f8d8L,0x10fb38L,0x114a50L,0x12f308L,0x1134a8L,
        0x1134c8L,0x114b28L,0x11a210L,0x11a650L,0x12f3c0L,0x10d720L,0x10d638L,
        0x10d680L,0x111738L,0x114470L,0x1fdc64L,0x111560L,0x12c6f8L,0x12c428L,
        0x1253e8L,0x124d48L,0x1134c0L,0x124e38L,0x119de8L,0x100e38L,0x100e78L,
        0x100ec8L,0x100fd8L,0x1fda0cL,0x1050b8L,0x175f78L);
    private static final String[] REGS={"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3","t4","t5","t6","t7",
        "s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","s8","ra"};
    private Address at(long value){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);}
    private static String sha(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    private static long word(byte[]b,long a){int p=(int)a;return (b[p]&255L)|((b[p+1]&255L)<<8)|((b[p+2]&255L)<<16)|((b[p+3]&255L)<<24);}
    private static void need(boolean valid,String message){if(!valid)throw new IllegalStateException(message);}
    @Override public void run()throws Exception{
        String[]args=getScriptArgs();need(args.length==3,"Expected new evidence directory, source ELF and validated native bootstrap report");
        Path out=Path.of(args[0]);need(!Files.exists(out),"Output exists");Files.createDirectory(out);
        byte[]elf=Files.readAllBytes(Path.of(args[1]));need(sha(elf).equals(ELF)&&ELF.equalsIgnoreCase(currentProgram.getExecutableSHA256()),"ELF differs");
        byte[]report=Files.readAllBytes(Path.of(args[2]));
        var source=JsonParser.parseString(new String(report,java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
        var retained=source.getAsJsonArray("cases").asList().stream().map(x->x.getAsJsonObject()).filter(x->!x.get("preserved_ram").isJsonNull()).findFirst().orElseThrow();
        byte[]ram=Files.readAllBytes(Path.of(retained.get("preserved_ram").getAsString()));
        need(sha(ram).equals(retained.get("ram_sha256").getAsString())&&ram.length==0x2000000,"Cold RAM differs");
        need(Arrays.equals(Arrays.copyOfRange(ram,0x100000,0x204b38),Arrays.copyOfRange(elf,0x1000,0x105b38)),"ELF text differs");
        long manager=word(ram,0x235e40),context=word(ram,manager+0x40),script=word(ram,manager+0x38),cursor=word(ram,script+0xd8);
        long opcode=ram[(int)cursor]&255,handler=word(ram,manager+0x5c+opcode*4),target=word(ram,word(ram,handler)+60);
        need(opcode==0x22&&target==0x12f8d8,"Cold source first command differs");
        var e=new EmulatorHelper(currentProgram);var trace=new ArrayList<Object>();var calls=new LinkedHashSet<Long>();
        var faults=new ArrayList<String>();var result=new LinkedHashMap<String,Object>();
        try {
            var mmi=new KamaitachiMmiUserops(e);var pcpyh=new KamaitachiPcpyh(e);
            e.setMemoryFaultHandler(new MemoryFaultHandler(){
                public boolean unknownAddress(Address a,boolean w){faults.add(a.toString());return false;}
                public boolean uninitializedRead(Address a,int n,byte[]b,int o){faults.add(a.toString());return false;}
            });
            e.writeMemory(at(0),ram);for(String reg:REGS)e.writeRegister(reg+"_qw",BigInteger.ZERO);
            for(int i=0;i<32;i++)e.writeRegister("f"+i,0);
            e.writeRegister("gp",0x23daf0);e.writeRegister("sp",0x1ff0000);e.writeRegister("ra",0x3ff000);
            e.writeRegister("a0",context);e.writeRegister("a1",manager);
            e.writeRegister(e.getPCRegister(),word(ram,word(ram,context)+4));
            String reason="step_limit";long tail=0;
            for(int i=0;i<10000;i++){
                monitor.checkCancelled();long pc=e.getExecutionAddress().getOffset();tail=pc;
                var f=currentProgram.getFunctionManager().getFunctionContaining(at(pc));
                long functionEntry=f==null?0:f.getEntryPoint().getOffset();
                boolean scriptDataBody=functionEntry>=0x10d3d0 && functionEntry<=0x10fac8;
                // 100FD8 dispatches by the original 16-entry comparison table
                // at 227FC0. Ghidra leaves several tiny target arms unowned.
                boolean comparisonArm=pc>=0x10100c && pc<0x101054 && calls.contains(0x100fd8L);
                if(!comparisonArm&&(f==null||(!PREFIX.contains(functionEntry)&&!scriptDataBody))){
                    reason=pc==0x12f1d0?"first unconstructed font/preferences service":
                           pc==0x100e38||pc==0x100e78?"first original variable comparison; requires 100D40 variable store":
                           pc==0x10d868?"lookahead delegates source label/history transition":
                           pc==0x104e10?"first unconstructed autosave/file service":"outside bounded first-command prefix";
                    break;
                }
                need(pc>=0x100000&&pc+4<=0x204b38,"Original text escaped");
                byte[]raw=Arrays.copyOfRange(elf,(int)pc-0xff000,(int)pc-0xff000+4);
                need(Arrays.equals(raw,e.readMemory(at(pc),4)),"Original instruction differs");
                if(functionEntry==pc)calls.add(pc);
                if(pc==target)result.put("observed_handler_arguments",Map.of("a0",e.readRegister("a0").longValue(),"a1",e.readRegister("a1").longValue(),"a2",e.readRegister("a2").longValue(),"a3",e.readRegister("a3").longValue()));
                boolean ok=e.step(monitor);
                trace.add(Map.of("pc",String.format("0x%08x",pc),"hex",HexFormat.of().formatHex(raw),"ok",ok));
                need(ok&&faults.isEmpty(),"Original prefix emulation fault: "+e.getLastError()+" "+faults);
            }
            need(calls.contains(0x120308L)&&calls.contains(0x1203e0L)&&calls.contains(target),"Original dispatch did not enter real handler");
            result.put("status","source_prefix_observed");result.put("first_opcode_completed",false);
            result.put("frontier_reason",reason);result.put("frontier_pc",String.format("0x%08x",tail));
            result.put("entered_functions",calls.stream().map(a->String.format("0x%08x",a)).toList());
            result.put("steps",trace.size());result.put("mmi_executions",mmi.counts);result.put("pcpyh_executions",pcpyh.executions);
        } finally {
            e.dispose();result.put("source_elf_sha256",ELF);result.put("source_ram_sha256",sha(ram));result.put("bootstrap_report_sha256",sha(report));
            result.put("source","Original instructions on independently constructed native RAM. Prefix stops before a new unverified function or external service.");
            result.put("faults",faults);result.put("trace",trace);Files.writeString(out.resolve("manifest.json"),new GsonBuilder().setPrettyPrinting().create().toJson(result));
        }
    }
}
