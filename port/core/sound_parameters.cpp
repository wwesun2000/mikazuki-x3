#include "sound_parameters.hpp"
#include "ee_scalar.hpp"
#include "guest_memory.hpp"
#include <algorithm>
#include <cstring>

namespace kx3 {
namespace {
using namespace ee;
constexpr u32 return_pc=0x3ff000, gains=0x300000;
struct PS2Runtime {
    const GuestMemory* memory=nullptr;
    float factors[2]{};
    unsigned fuel=64;
    bool eeCheckpointDue(){
        if(!fuel--)throw std::runtime_error("1B0D38 exceeded signed cue pitch range");
        return false;
    }
    void handleBreak(std::uint8_t*,R5900Context*){throw std::runtime_error("Unexpected 1B0D54 division trap");}
    u32 read(u32 p)const{
        if(memory && p>=0x238298 && p<=0x2382ac && !(p&3))return memory->read_u32(p);
        if(p==0x2336f8)return std::bit_cast<u32>(8.f); // retail pan scale
        if(p==gains || p==gains+4)return std::bit_cast<u32>(factors[(p-gains)/4]);
        throw std::runtime_error("Unmapped EE sound parameter address");
    }
};
#define READ32(p) runtime->read(p)
#define FAST_READ32(p) READ32(p)
#define GPR_S32(c,n) std::bit_cast<i32>((c)->word(n))
#define GPR_S64(c,n) std::bit_cast<std::int64_t>((c)->r[n].lo)
#define FPU_MUL_S(a,b) round_towards_zero(double(a)*double(b))
#define FPU_CVT_W_S(a) static_cast<i32>(std::clamp(double(ordinary(a)),double(INT32_MIN),double(INT32_MAX)))
#include "sound_generated.hpp"

using Leaf=void(*)(std::uint8_t*,R5900Context*,PS2Runtime*);
void execute(Leaf fn,R5900Context& c,PS2Runtime& host){
    c.set32(31,return_pc);
    fn(nullptr,&c,&host);
    if(c.pc!=return_pc || c.in_delay_slot)throw std::runtime_error("EE sound helper failed to return");
}
}
float source_pitch_multiplier(const GuestMemory& m,std::int32_t cents){
    if(cents<INT16_MIN || cents>INT16_MAX)throw std::runtime_error("Pitch outside signed cue range");
    R5900Context c;PS2Runtime host{&m};c.set32(4,u32(cents));
    execute(FUN_001b0d38_0x1b0d38,c,host);return c.f[0];
}
unsigned source_pitch_register(unsigned base,float multiplier){
    R5900Context c;PS2Runtime host;c.set32(4,base);c.f[12]=multiplier;
    execute(FUN_001d3504_0x1d3504,c,host);return c.word(2);
}
unsigned source_pan_index(float normalized){
    R5900Context c;PS2Runtime host;c.f[12]=normalized;
    execute(FUN_001d34d0_0x1d34d0,c,host);return c.word(2);
}
unsigned source_volume_register(unsigned base,float left,float right){
    R5900Context c;PS2Runtime host{nullptr,{left,right}};c.set32(4,base);c.set32(5,gains);
    execute(FUN_001d3530_0x1d3530,c,host);return c.word(2);
}
void SoundPitch::set(float multiplier,std::uint32_t ticks){
    target=multiplier;
    if(!ticks){current=target;step=0;return;}
    // 1B1DD8 -> 1D2E0C. Preserve the two original float operations on duration.
    const float seconds=float(ticks)/60.f;
    step=ee::ee_add_sub(target,current,true)/ee::round_towards_zero(double(seconds)*60.f);
}
void SoundPitch::advance(){
    if(!step)return;
    current=ee::ee_add_sub(current,step,false);
    if(step<0?current<target:current>target){current=target;step=0;} // 1D3224, strict crossing
}
}
