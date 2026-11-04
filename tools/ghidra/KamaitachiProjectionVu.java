// Isolated missing CALLOTHER semantics for the six fixed retail VU0 matrix
// leaves. The original EE shell, branches, delay slots and loads still run.
// Vector lane/mask conventions cross-checked against the PCSX2 VU interpreter:
// https://github.com/PCSX2/pcsx2/blob/master/pcsx2/VUops.cpp
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;

@SuppressWarnings("removal")
public final class KamaitachiProjectionVu {
    static final String[] OPS={"_lqc2","_sqc2","_qmtc2","_vadd","_vsub","_vmul","_vaddbc","_vsubbc",
        "_vmulbc","_vmulabc","_vmaddabc","_vmaddbc","_vaddq","_vmulq","_vdiv","_vsqrt","_vmr32",
        "_vmove","_vnop","_vwaitq"};
    static final BigInteger MASK=BigInteger.valueOf(0xffffffffL);
    public final Map<String,Integer> counts=new TreeMap<>();
    static float lane(BigInteger v,int i){return Float.intBitsToFloat(v.shiftRight(32*i).intValue());}
    static BigInteger raw(float v){return BigInteger.valueOf(Integer.toUnsignedLong(Float.floatToRawIntBits(v)));}
    static boolean valid(long p){
        return p>=0x17ad38&&p<0x17ad4c || p>=0x17adb8&&p<0x17ae0c || p>=0x1c1590&&p<0x1c15d4 ||
            p>=0x1c17e0&&p<0x1c180c || p>=0x1c1888&&p<0x1c1924 || p>=0x1c1928&&p<0x1c19cc;
    }
    public KamaitachiProjectionVu(EmulatorHelper e,byte[] binary){
        ByteBuffer elf=ByteBuffer.wrap(binary).order(ByteOrder.LITTLE_ENDIAN);
        for(int i=0;i<32;i++)e.writeRegister("vf"+i,BigInteger.ZERO);
        e.writeRegister("vf0",raw(1.0f).shiftLeft(96));e.writeRegister("vuACC",BigInteger.ZERO);
        e.writeRegister("vuQ",BigInteger.ZERO);
        for(String opName:OPS)e.registerCallOtherCallback(opName,new BreakCallBack(){
            @Override public boolean pcodeCallback(PcodeOpRaw op){
                long pc=op.getAddress().getOffset();
                int word=elf.getInt((int)pc-0xff000),primary=word>>>26;
                if(primary!=0x12 && primary!=54 && primary!=62){
                    // Ghidra attributes an incorporated delay slot to its branch.
                    pc+=4;word=elf.getInt((int)pc-0xff000);
                }
                if(!valid(pc))throw new IllegalStateException("Projection VU outside reviewed range "+Long.toHexString(pc));
                var state=emulate.getMemoryState();
                counts.merge(opName,1,Integer::sum);
                if(opName.equals("_vnop")||opName.equals("_vwaitq"))return true;
                if(opName.equals("_lqc2")||opName.equals("_sqc2")||opName.equals("_qmtc2")){
                    // This source QMT uses GPR t0, including its full 128 bits.
                    BigInteger v=opName.equals("_qmtc2")?e.readRegister("t0_qw"):state.getBigInteger(op.getInput(1),false);
                    state.setValue(op.getOutput(),v);return true;
                }
                int fs=(word>>>11)&31,ft=(word>>>16)&31,fd=(word>>>6)&31;
                BigInteger left=e.readRegister("vf"+fs),right=e.readRegister("vf"+ft);
                BigInteger acc=e.readRegister("vuACC");float q=lane(e.readRegister("vuQ"),0);
                if(opName.equals("_vdiv")||opName.equals("_vsqrt")){
                    float t=lane(right,(word>>>23)&3);
                    float result=opName.equals("_vdiv")?lane(left,(word>>>21)&3)/t:(float)Math.sqrt(Math.abs(t));
                    if(!Float.isFinite(result))throw new IllegalStateException("Projection fixture escaped finite Q");
                    state.setValue(op.getOutput(),raw(result));return true;
                }
                boolean writesAcc=opName.equals("_vmulabc") || opName.equals("_vmaddabc");
                BigInteger result=writesAcc?acc:e.readRegister("vf"+((opName.equals("_vmr32")||opName.equals("_vmove"))?ft:fd));
                for(int i=0;i<4;i++){
                    if((word&(1<<(24-i)))==0)continue;
                    float a=lane(left,i),b=lane(right,opName.endsWith("bc")?word&3:i);
                    float v=switch(opName){
                        case "_vadd","_vaddbc" -> a+b;
                        case "_vsub","_vsubbc" -> a-b;
                        case "_vmul","_vmulbc","_vmulabc" -> a*b;
                        case "_vmaddabc","_vmaddbc" -> lane(acc,i)+a*b;
                        case "_vaddq" -> a+q;
                        case "_vmulq" -> a*q;
                        case "_vmove" -> a;
                        case "_vmr32" -> lane(left,(i+1)&3);
                        default -> throw new IllegalStateException(opName);
                    };
                    if(!Float.isFinite(v))throw new IllegalStateException("Projection fixture escaped finite lanes");
                    result=result.andNot(MASK.shiftLeft(32*i)).or(raw(v).shiftLeft(32*i));
                }
                state.setValue(op.getOutput(),result);
                return true;
            }
        });
    }
}
