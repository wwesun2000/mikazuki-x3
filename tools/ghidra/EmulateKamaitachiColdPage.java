// Execute the original default context once, from a native from-file cold input.
// @category Kamaitachi.Evidence
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.program.model.address.*;

@SuppressWarnings("removal")
public class EmulateKamaitachiColdPage extends GhidraScript {
    private static final String ELF_SHA = "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160";
    private static final int RAM_SIZE = 0x2000000, SP = 0x1ff0000, RETURN = 0x3ff000;
    private static final String[] REGS = {"zero","at","v0","v1","a0","a1","a2","a3","t0","t1","t2","t3",
        "t4","t5","t6","t7","s0","s1","s2","s3","s4","s5","s6","s7","t8","t9","k0","k1","gp","sp","s8","ra"};
    private static final Gson JSON = new GsonBuilder().setPrettyPrinting().create();
    private Address at(long n) { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(n); }
    private static void need(boolean ok, String message) { if (!ok) throw new IllegalStateException(message); }
    private static String hex(byte[] b) { return HexFormat.of().formatHex(b); }
    private static String sha(byte[] b) throws Exception { return hex(MessageDigest.getInstance("SHA-256").digest(b)); }
    private static int word(byte[] b, int a) {
        return (b[a]&255) | ((b[a+1]&255)<<8) | ((b[a+2]&255)<<16) | ((b[a+3]&255)<<24);
    }

    private Map<String,Object> execute(byte[] ram, byte[] elf, JsonObject input) throws Exception {
        var result = new LinkedHashMap<String,Object>();
        result.put("id",input.get("id").getAsString());
        result.put("input_sha256",sha(ram));
        need(ram.length == RAM_SIZE && sha(ram).equals(input.get("pre_sha256").getAsString()), "RAM identity changed");
        need(Arrays.equals(ram,0x100000,0x204b38,elf,0x1000,0x105b38),"Original text differs");
        int manager=word(ram,0x235e40), context=word(ram,manager+0x40), script=word(ram,manager+0x38);
        int cursor=word(ram,script+0xd8), op=Byte.toUnsignedInt(ram[cursor]);
        int entry=word(ram,word(ram,context)+4), target=word(ram,word(ram,word(ram,manager+0x5c+4*op))+60);
        need(entry==0x120308 && op==0x22 && target==0x12f8d8 && word(ram,manager+0x2b4)==0,"Unexpected entry");
        var e=new EmulatorHelper(currentProgram);
        var faults=new ArrayList<String>();
        int steps=0;
        try {
            var mmi=new KamaitachiMmiUserops(e);
            var pcpyh=new KamaitachiPcpyh(e);
            e.setMemoryFaultHandler(new MemoryFaultHandler(){
                public boolean unknownAddress(Address a,boolean write){faults.add("unknown "+a+" write="+write);return false;}
                public boolean uninitializedRead(Address a,int n,byte[] b,int o){faults.add("uninitialized "+a+" size="+n);return false;}
            });
            e.writeMemory(at(0),ram.clone());
            for(String name:REGS)e.writeRegister(name+"_qw",BigInteger.ZERO);
            for(int i=0;i<32;i++)e.writeRegister("f"+i,BigInteger.ZERO);
            for(String f:new String[]{"fir","fccr","fexr","fenr","fcsr"})e.writeRegister(f,BigInteger.ZERO);
            e.writeRegister("pc_qw",BigInteger.ZERO); e.writeRegister("gp",0x23daf0);
            e.writeRegister("sp",SP); e.writeRegister("ra",RETURN);
            e.writeRegister("a0",context); e.writeRegister("a1",manager); e.writeRegister(e.getPCRegister(),entry);
            e.enableMemoryWriteTracking(true);
            boolean handler=false;
            var path=MessageDigest.getInstance("SHA-256");
            ByteBuffer pcBytes=ByteBuffer.allocate(4);
            var entered=new TreeSet<String>();
            while(e.getExecutionAddress().getOffset()!=RETURN){
                monitor.checkCancelled();
                long pc=e.getExecutionAddress().getOffset();
                result.put("last_pc",String.format("0x%08x",pc));
                need(steps<250000 && pc>=0x100000 && pc<=0x204b34,"Outside step or ELF text bound");
                int offset=(int)pc-0xff000;
                need(Arrays.equals(e.readMemory(at(pc),4),0,4,elf,offset,offset+4),"Fetched instruction differs from ELF");
                pcBytes.clear(); pcBytes.putInt((int)pc);
                path.update(pcBytes.array()); path.update(elf,offset,4);
                handler|=pc==target;
                var fn=currentProgram.getFunctionManager().getFunctionAt(at(pc));
                if(fn!=null)entered.add(String.format("0x%08x",pc));
                steps++;
                need(e.step(monitor)&&faults.isEmpty(),"Source execution fault "+faults+" "+e.getLastError());
            }
            need(handler,"First context did not execute 12F8D8");
            byte[] normalized=e.readMemory(at(0),RAM_SIZE);
            var persistent=new ArrayList<Object>();
            var stack=new ArrayList<Object>();
            for(var range:e.getTrackedMemoryWriteSet().getAddressRanges()){
                if(!range.getMinAddress().getAddressSpace().getName().equals("ram"))continue;
                int a=Math.toIntExact(range.getMinAddress().getOffset()), n=Math.toIntExact(range.getLength());
                need(a>=0 && n<=RAM_SIZE-a,"Out-of-RAM source write");
                var row=Map.of("address",a,"size",n,"hex",hex(Arrays.copyOfRange(normalized,a,a+n)));
                if(a>=SP-0x1000 && a+n<=SP+0x100) {
                    stack.add(row); System.arraycopy(ram,a,normalized,a,n);
                } else persistent.add(row);
            }
            result.put("status","returned"); result.put("entry",entry); result.put("handler",target);
            result.put("return_v0_u64",e.readRegister("v0").and(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)).toString());
            result.put("cursor_before",cursor); result.put("cursor_after",word(normalized,script+0xd8));
            result.put("selector_after",word(normalized,script+0xd0)); result.put("label_after",word(normalized,script+0xd4));
            result.put("persistent_writes",persistent); result.put("abi_stack_writes",stack);
            result.put("persistent_ram_sha256",sha(normalized)); result.put("executed_pc_opcode_sha256",hex(path.digest()));
            result.put("entered_defined_functions",entered); result.put("mmi_calls",mmi.counts); result.put("pcpyh_calls",pcpyh.executions);
        } catch(Exception ex) {
            result.put("status","failed"); result.put("reason",ex.toString()); result.put("faults",faults);
        } finally {e.dispose();}
        result.put("steps",steps);
        return result;
    }

    @Override public void run() throws Exception {
        String[] args=getScriptArgs(); need(args.length==4,"Expected output, original ELF, native input plan and extension directory");
        Path out=Path.of(args[0]), helpers=Path.of(getSourceFile().getParentFile().getAbsolutePath());
        Files.createDirectory(out);
        byte[] elf=Files.readAllBytes(Path.of(args[1])), planBytes=Files.readAllBytes(Path.of(args[2]));
        need(sha(elf).equals(ELF_SHA)&&ELF_SHA.equalsIgnoreCase(currentProgram.getExecutableSHA256()),"Incorrect original");
        need(currentProgram.getLanguageID().toString().equals("r5900:LE:32:default"),"Incorrect processor");
        var plan=JsonParser.parseString(new String(planBytes,java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
        var cases=new ArrayList<Map<String,Object>>();
        var manifest=new LinkedHashMap<String,Object>();
        var sourceHashes=new TreeMap<String,String>();
        for(String f:new String[]{"EmulateKamaitachiColdPage.java","KamaitachiMmiUserops.java","KamaitachiPcpyh.java"}){
            byte[] bytes=Files.readAllBytes(helpers.resolve(f)); Files.write(out.resolve(f),bytes); sourceHashes.put(f,sha(bytes));
        }
        for(String name:new String[]{"extension.properties","data/languages/r5900.sla","data/languages/base.sinc","data/languages/mips.sinc","data/languages/r5900.cspec"})
            sourceHashes.put(name,sha(Files.readAllBytes(Path.of(args[3]).resolve(name))));
        manifest.put("elf_sha256",ELF_SHA); manifest.put("ghidra_version",Application.getApplicationVersion());
        manifest.put("engine","R5900 Ghidra EmulatorHelper with audited MMI helpers; source bytes checked at each step");
        manifest.put("input_scope","Native cold constructor creates the shared input; comparison begins at the first context method.");
        manifest.put("plan_sha256",sha(planBytes)); manifest.put("source_hashes",sourceHashes);
        Files.write(out.resolve("input-plan.json"),planBytes);
        for(var row:plan.getAsJsonArray("cases")){
            var c=row.getAsJsonObject(); cases.add(execute(Files.readAllBytes(Path.of(c.get("pre_path").getAsString())),elf,c));
        }
        manifest.put("cases",cases); manifest.put("status",cases.stream().allMatch(c->"returned".equals(c.get("status")))?"oracle_completed":"oracle_failed");
        Files.writeString(out.resolve("manifest.json"),JSON.toJson(manifest));
        println("Cold page oracle: "+manifest.get("status")+" ("+cases.size()+" cases)");
    }
}
