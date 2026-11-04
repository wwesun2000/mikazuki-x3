#include "visual_trig.hpp"
#include "guest_memory.hpp"
#include "ee_scalar.hpp"
#include <algorithm>
#include <array>
#include <sstream>

namespace kx3 {
namespace {
using namespace ee;
constexpr u32 stack_base=0x70001000,stack_top=stack_base+512,return_pc=0x70002000;
struct PS2Runtime {
    enum class GuestBranchKind{DirectCall,DirectJump,IndirectJump,Return};
    const GuestMemory& memory;
    std::array<std::uint8_t,512> stack{};
    unsigned budget=128;
    bool eeCheckpointDue(){
        if(!budget--)throw std::runtime_error("Original visual trigonometry exceeded bounded loops");
        return false;
    }
    u64 read(u32 address,unsigned size)const{
        if(address>=stack_base && address-stack_base<=stack.size()-size){
            u64 value=0;for(unsigned i=0;i<size;++i)value|=u64(stack[address-stack_base+i])<<(8*i);
            return value;
        }
        if(address<0x234b00 || address+size>0x235100){
            std::ostringstream out;out<<"Undeclared original trig read 0x"<<std::hex<<address;
            throw std::runtime_error(out.str());
        }
        const auto bytes=memory.bytes(address,size);u64 value=0;
        for(unsigned i=0;i<size;++i)value|=u64(bytes[i])<<(8*i);
        return value;
    }
    void write(u32 address,u64 value,unsigned size){
        if(address<stack_base || address-stack_base>stack.size()-size)
            throw std::runtime_error("Original trig write escaped its private stack");
        for(unsigned i=0;i<size;++i)stack[address-stack_base+i]=std::uint8_t(value>>(8*i));
    }
    bool dispatchGuestBranch(std::uint8_t*,R5900Context*,u32 target,u32 pc,u32 resume,GuestBranchKind,const char*);
};
#define READ32(p) u32(runtime->read(p,4))
#define FAST_READ32(p) READ32(p)
#define READ64(p) runtime->read(p,8)
#define WRITE32(p,v) runtime->write(p,u32(v),4)
#define WRITE64(p,v) runtime->write(p,u64(v),8)
#define GPR_S32(c,n) std::bit_cast<i32>((c)->word(n))
#define GPR_S64(c,n) std::bit_cast<std::int64_t>((c)->r[n].lo)
#define SLL32(v,s) (u32(v)<<((s)&31))
#define SRL32(v,s) (u32(v)>>((s)&31))
#define SRA32(v,s) (std::bit_cast<i32>(u32(v))>>((s)&31))
#define SUB32(a,b) (u32(a)-u32(b))
#define FPU_CVT_W_S(a) static_cast<i32>(std::clamp(double(ordinary(a)),double(INT32_MIN),double(INT32_MAX)))
#define FPU_MUL_S(a,b) round_towards_zero(double(ordinary(a))*double(ordinary(b)))
#define FPU_NEG_S(a) (-ordinary(a))
#define FPU_SET_ACC(c,v) ((c)->f_acc=(v))
#define PS2X_STRICT_RETURN_DIAGNOSTICS 1
#include "visual_trig_generated.hpp"
#undef PS2X_STRICT_RETURN_DIAGNOSTICS

bool PS2Runtime::dispatchGuestBranch(std::uint8_t* ram,R5900Context* context,u32 target,u32 pc,u32 resume,
                                    GuestBranchKind kind,const char*){
    if(context->in_delay_slot || context->pc!=target)throw std::runtime_error("Original trig transfer preceded its delay slot");
    if(kind==GuestBranchKind::Return)return false;
    if(kind!=GuestBranchKind::DirectCall && kind!=GuestBranchKind::DirectJump)
        throw std::runtime_error("Unrecovered indirect visual trig transfer");
    using Function=void(*)(std::uint8_t*,R5900Context*,PS2Runtime*);
    Function function=nullptr;
    switch(target){
    case 0x1f4d40:function=FUN_001f4d40_0x1f4d40;break;
    case 0x1f3cb0:function=FUN_001f3cb0_0x1f3cb0;break;
    case 0x1f4620:function=FUN_001f4620_0x1f4620;break;
    case 0x1f4718:function=FUN_001f4718_0x1f4718;break;
    case 0x1f29d8:function=FUN_001f29d8_0x1f29d8;break;
    case 0x1f0838:function=FUN_001f0838_0x1f0838;break;
    case 0x1f08f0:function=FUN_001f08f0_0x1f08f0;break;
    default:{std::ostringstream out;out<<"Unrecovered visual trig edge 0x"<<std::hex<<pc<<" -> 0x"<<target;
        throw std::runtime_error(out.str());}
    }
    const auto destination=context->word(31);
    if(kind==GuestBranchKind::DirectCall && (destination!=resume || resume!=pc+8))
        throw std::runtime_error("Original trig call changed its link register");
    function(ram,context,this);
    if(context->pc!=destination)throw std::runtime_error("Original nested trig return differs");
    return kind==GuestBranchKind::DirectCall;
}

float evaluate(const GuestMemory& memory,float phase,bool tangent){
    if(!std::isfinite(phase) || std::abs(phase)>std::bit_cast<float>(0x40490fdbu))
        throw std::runtime_error("Visual trig phase exceeds the recovered [-pi,pi] domain");
    PS2Runtime runtime{memory};R5900Context context;
    context.f[12]=phase;context.set32(28,0x23daf0);context.set32(29,stack_top);context.set32(31,return_pc);
    context.pc=tangent?0x1f08f0:0x1f0838;
    if(tangent)FUN_001f08f0_0x1f08f0(nullptr,&context,&runtime);
    else FUN_001f0838_0x1f0838(nullptr,&context,&runtime);
    if(context.pc!=return_pc || context.in_delay_slot || context.word(29)!=stack_top)
        throw std::runtime_error("Original visual trig return differs from its EE ABI");
    return context.f[0];
}
}
float source_visual_sine(const GuestMemory& memory,float phase){return evaluate(memory,phase,false);}
float source_visual_tangent(const GuestMemory& memory,float phase){return evaluate(memory,phase,true);}
}
