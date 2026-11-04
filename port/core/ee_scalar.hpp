#pragma once
#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace kx3::ee {
using u32=std::uint32_t;
using u64=std::uint64_t;
using i32=std::int32_t;

// Independent private ABI for these generated functions only. Scalar MIPS writes
// preserve the upper 64 bits, whereas POR/MOVZ/MOVN and SQ use all 128 bits.
struct alignas(16) Quad {u64 lo=0,hi=0;};
struct R5900Context {
    std::array<Quad,32> r{};
    std::array<float,32> f{};
    float f_acc=0;
    u64 hi=0,lo=0,hi1=0,lo1=0;
    u32 fcr31=0,pc=0,branch_pc=0;
    bool in_delay_slot=false;
    void set64(unsigned reg,u64 v){if(reg)r[reg].lo=v;}
    void set32(unsigned reg,u32 v){set64(reg,u64(std::int64_t(std::bit_cast<i32>(v))));}
    void set128(unsigned reg,Quad v){if(reg)r[reg]=v;}
    u32 word(unsigned reg)const{return u32(r[reg].lo);}
};

inline float ordinary(float f){
    // The recovered effect coordinates and sound parameters use normal
    // single-precision values and zero within their supported input ranges.
    if(!std::isnormal(f) && f!=0.f)throw std::runtime_error("Unsupported EE scalar input");
    return f;
}

inline float round_towards_zero(double exact){
    const float result=static_cast<float>(exact);
    if(std::abs(double(result))<=std::abs(exact))return result;
    return std::bit_cast<float>(std::bit_cast<u32>(result)-1);
}

inline float ee_add_sub(float left,float right,bool subtract){
    // On an EE, aligning the smaller operand retains one guard bit. Verified
    // against the PCSX2 EE readbacks in analysis/native-core/expandband-ee-reference.
    // Plain IEEE subtraction first diverges at update 77 of the disc's 180.
    u32 a=std::bit_cast<u32>(ordinary(left));
    u32 b=std::bit_cast<u32>(ordinary(right));
    const int gap=int((a>>23)&255)-int((b>>23)&255);
    const auto align=[](u32 bits,int distance){
        return distance>=25 ? bits&0x80000000u : bits&(~u32(0)<<(distance-1));
    };
    if(gap>0)b=align(b,gap);
    if(gap<0)a=align(a,-gap);
    if(subtract)b^=0x80000000u;
    // After alignment both operands span at most 25 significant bit positions.
    // Their exact sum fits in binary64. Select the binary32 neighbor towards zero.
    const double exact=double(std::bit_cast<float>(a))+double(std::bit_cast<float>(b));
    if(exact==0.0)return std::bit_cast<float>(a&b&0x80000000u);
    const double magnitude=std::abs(exact);
    if(magnitude<std::numeric_limits<float>::min() || magnitude>std::numeric_limits<float>::max())
        throw std::runtime_error("Unsupported EE scalar underflow or overflow");
    return round_towards_zero(exact);
}

}

#define ADD32(a,b) (u32(a)+u32(b))
#define GPR_U32(c,n) ((c)->word(n))
#define GPR_U64(c,n) ((c)->r[n].lo)
#define GPR_VEC(c,n) ((c)->r[n])
#define SET_GPR_U32(c,n,v) (c)->set32(n,u32(v))
#define SET_GPR_S32(c,n,v) (c)->set32(n,u32(v))
#define SET_GPR_U64(c,n,v) (c)->set64(n,u64(v))
#define SET_GPR_VEC(c,n,v) (c)->set128(n,v)
#define FPU_CVT_S_W(a) round_towards_zero(double(std::int32_t(a)))
#define FPU_MOV_S(a) (a)
#define FPU_C_EQ_S(a,b) (ordinary(a)==ordinary(b))
#define FPU_C_OLT_S(a,b) (ordinary(a)<ordinary(b))
#define FPU_ADD_S(a,b) ee_add_sub(a,b,false)
#define FPU_SUB_S(a,b) ee_add_sub(a,b,true)
#define FPU_DIV_S(a,b) ordinary(ordinary(a)/ordinary(b))
