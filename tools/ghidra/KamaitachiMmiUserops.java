// Isolated oracle-engine extension, not original Ghidra R5900 support.
// Semantics independently expressed from PCSX2's documented lane operations.
import java.math.BigInteger;
import java.util.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.memstate.MemoryState;
import ghidra.pcode.pcoderaw.PcodeOpRaw;

@SuppressWarnings("removal")
public final class KamaitachiMmiUserops {
    public static final String[] NAMES={"_pcpyld","_pcpyud","_psubb","_psubw","_pand","_por"};
    private static final BigInteger M64=BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
    private static final BigInteger M128=BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
    public final Map<String,Long> counts=new LinkedHashMap<>();
    public static BigInteger evaluate(String name,BigInteger rs,BigInteger rt) {
        rs=rs.and(M128);rt=rt.and(M128);
        switch(name) {
            case "_pcpyld": return rs.and(M64).shiftLeft(64).or(rt.and(M64));
            case "_pcpyud": return rt.shiftRight(64).shiftLeft(64).or(rs.shiftRight(64));
            case "_pand": return rs.and(rt);
            case "_por": return rs.or(rt);
            case "_psubb": return subtractLanes(rs,rt,8);
            case "_psubw": return subtractLanes(rs,rt,32);
            default: throw new IllegalArgumentException("Unsupported MMI userop: "+name);
        }
    }
    private static BigInteger subtractLanes(BigInteger rs,BigInteger rt,int bits) {
        BigInteger mask=BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE),out=BigInteger.ZERO;
        for(int bit=0;bit<128;bit+=bits)
            out=out.or(rs.shiftRight(bit).and(mask).subtract(rt.shiftRight(bit).and(mask)).and(mask).shiftLeft(bit));
        return out;
    }
    public KamaitachiMmiUserops(EmulatorHelper helper) {
        if(!helper.getLanguage().getLanguageID().toString().equals("r5900:LE:32:default"))
            throw new IllegalArgumentException("Only audited R5900 language is accepted");
        for(String name:NAMES) {
            counts.put(name,0L);
            helper.registerCallOtherCallback(name,new BreakCallBack() {
                @Override public boolean pcodeCallback(PcodeOpRaw op) {
                    if(op.getNumInputs()!=3 || op.getOutput()==null || op.getOutput().getSize()!=16 ||
                        op.getInput(1).getSize()!=16 || op.getInput(2).getSize()!=16)
                        throw new IllegalStateException("Unexpected 128-bit MMI signature: "+name);
                    MemoryState state=emulate.getMemoryState();
                    // Capture both sources before writing: RD may alias either source.
                    BigInteger rs=state.getBigInteger(op.getInput(1),false);
                    BigInteger rt=state.getBigInteger(op.getInput(2),false);
                    BigInteger result=evaluate(name,rs,rt);
                    if(!(op.getOutput().isRegister() && op.getOutput().getOffset()==0))
                        state.setValue(op.getOutput(),result);
                    counts.put(name,counts.get(name)+1);
                    return true;
                }
            });
        }
        // No wildcard callback: every other unsupported operation still fails.
    }
}
