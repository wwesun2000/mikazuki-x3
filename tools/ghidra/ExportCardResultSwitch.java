// @category Kamaitachi.Evidence
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
public class ExportCardResultSwitch extends GhidraScript {
    void bindTable(int entry,int end,int jump,int base,int count) throws Exception {
        var start=toAddr(entry);
        var function=getFunctionAt(start);
        var limit=new AddressSet(start,toAddr(end-1));
        var refs=currentProgram.getReferenceManager();
        if(getInt(toAddr(jump))!=0x01a00008 || getInt(toAddr(jump+4))!=0 ||
           getInt(toAddr(jump-4))!=0x8ded0000 || getInt(toAddr(jump-8))!=0x01ee7821 ||
           getInt(toAddr(jump-12))!=(0x25ce0000|(base&0xffff)) ||
           (getInt(toAddr(jump-20))!=(0x3c0e0000|((base+0x8000)>>16)) &&
            getInt(toAddr(jump-16))!=(0x3c0e0000|((base+0x8000)>>16))))
            throw new IllegalStateException("Unbound indexed dispatch");
        for(int i=0;i<count;++i){
            var target=toAddr(getInt(toAddr(base+4*i)));
            if(!limit.contains(target) || (target.getOffset()&3)!=0)throw new IllegalStateException("Invalid card state");
            var existing=getFunctionContaining(target);
            if(existing!=null && !existing.equals(function))throw new IllegalStateException("Conflicting case owner");
            var cmd=new DisassembleCommand(target,limit,true);
            cmd.enableCodeAnalysis(false);cmd.applyTo(currentProgram,monitor);
            if(getInstructionAt(target)==null)throw new IllegalStateException("Card state not disassembled");
            refs.addMemoryReference(toAddr(jump),target,RefType.COMPUTED_JUMP,SourceType.USER_DEFINED,0);
        }
        var body=CreateFunctionCmd.getFunctionBody(currentProgram,start,monitor);
        if(!limit.contains(body))throw new IllegalStateException("Unresolved card switch");
        function.setBody(body);
    }
    public void run() throws Exception {
        if(!currentProgram.getExecutableSHA256().equalsIgnoreCase("50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160"))
            throw new IllegalStateException("Wrong ELF");
        // BEQ guard, SLL by 2, formation of 230D50, indexed LW, JR and its delay slot.
        int[] dispatch={0x11e00028,0x3c0e0023,0x00027880,0x25ce0d50,0x01ee7821,0x8ded0000,0x01a00008,0};
        for(int guard:new int[]{0x1a7cb8,0x1a7ccc,0x1a7cec})
            if(getInt(toAddr(guard))!=0x2c4f0032)throw new IllegalStateException("Unbound 50-state limit");
        for(int i=0;i<dispatch.length;++i)
            if(getInt(toAddr(0x1a7cf0+4*i))!=dispatch[i])throw new IllegalStateException("Unbound card dispatch");
        bindTable(0x1a7c88,0x1a8728,0x1a7d08,0x230d50,50);
        if(getInt(toAddr(0x1a4650))!=0x2c8f000a || getInt(toAddr(0x1a4720))!=0x2c8f000a ||
           getInt(toAddr(0x104a6c))!=0x2c8d0008)throw new IllegalStateException("Unbound card service limit");
        bindTable(0x1a4650,0x1a4720,0x1a4670,0x230840,10);
        bindTable(0x1a4720,0x1a4780,0x1a4740,0x230868,10);
        bindTable(0x1049f0,0x104b90,0x104a8c,0x2283d4,8);
        // 102E00 creates this request thread from the descriptor at 204C58.
        if(getInt(toAddr(0x204c58))!=0x103ca0 || getInt(toAddr(0x103d3c))!=0x2d8d0008 ||
           getInt(toAddr(0x103db0))!=0x2dcf0008 || getInt(toAddr(0x103e18))!=0x11e0001c)
            throw new IllegalStateException("Invalid card thread descriptor or dispatcher guard");
        if(getFunctionAt(toAddr(0x103ca0))==null && createFunction(toAddr(0x103ca0),"card_request_thread")==null)
            throw new IllegalStateException("Cannot recover 103CA0");
        bindTable(0x103ca0,0x103f58,0x103d5c,0x228324,8);
        bindTable(0x103ca0,0x103f58,0x103dcc,0x228344,8);
        bindTable(0x103ca0,0x103f58,0x103e34,0x228364,8);
        // 10BC78 calls slot +4 of the registered checkpoint objects.
        int[][] readers={{0x223644,0x113c88},{0x223624,0x1160f8},{0x223664,0x11a0a8},{0x2235fc,0x10f550}};
        for(int[] pair:readers){
            if(getInt(toAddr(pair[0]))!=pair[1])throw new IllegalStateException("Wrong checkpoint reader pointer");
            var address=toAddr(pair[1]);
            if(getFunctionAt(address)==null){
                if(getFunctionContaining(address)!=null)throw new IllegalStateException("Reader address has an existing owner");
                if(getInstructionAt(address)==null && !disassemble(address))throw new IllegalStateException("Cannot disassemble reader");
                if(createFunction(address,String.format("FUN_%08x",pair[1]))==null)throw new IllegalStateException("Cannot create reader");
            }
        }
        if(getInt(toAddr(0x117638))!=0x2c4f0086)throw new IllegalStateException("Wrong readback opcode bound");
        bindTable(0x117580,0x117840,0x117658,0x22a204,0x86);
        if(getInt(toAddr(0x100910))!=0x0c04d726 || getInt(toAddr(0x100914))!=0x2484c8d0 ||
           getInt(toAddr(0x10c8f0))!=0x08045c0c)throw new IllegalStateException("Unbound fade callback");
        if(getInt(toAddr(0x117078))!=0x0804e2e6)throw new IllegalStateException("Wrong fade completion tail jump");
        // Define tail callees first so Ghidra keeps each independently callable entry.
        for(int entry:new int[]{0x138b98,0x117030,0x10c8d0}){
            var address=toAddr(entry);
            if(getFunctionAt(address)==null){
                if(getFunctionContaining(address)!=null)throw new IllegalStateException("Existing owner at "+address+": "+getFunctionContaining(address));
                if(getInstructionAt(address)==null && !disassemble(address))throw new IllegalStateException("Cannot decode fade callback");
                if(createFunction(address,String.format("FUN_%08x",entry))==null)throw new IllegalStateException("Cannot create fade callback");
            }
        }
        runScript("ExportKamaitachiEvidence.java",getScriptArgs());
    }
}
