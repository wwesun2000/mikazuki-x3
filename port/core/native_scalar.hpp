#pragma once
#include "recovered.hpp"
#include "guest_memory.hpp"
#include <array>
#include <bit>

namespace kx3::scalar {
using u32=std::uint32_t;
using u64=std::uint64_t;
using i64=std::int64_t;
inline std::int32_t s32(u64 v){return std::bit_cast<std::int32_t>(u32(v));}
inline i64 s64(u64 v){return std::bit_cast<i64>(v);}
inline u64 sx32(u64 v){return u64(i64(s32(v)));}
struct ScalarRegisters {
    ScalarRegisters(GuestMemory& memory,ExecutionServices* execution):m(memory),services(execution){}
    GuestMemory& m;
    ExecutionServices* services;
    static constexpr u32 stack_start=0x1fff000;
    std::array<std::uint8_t,4096> stack{};
    u64 v0=0,v1=0,a0=0,a1=0,a2=0,a3=0,s0=0,s1=0,s2=0,s3=0,s4=0,s5=0,s6=0,s7=0,s8=0;
    u64 t0=0,t1=0,t2=0,t3=0,t4=0,t5=0,t6=0,t7=0,t8=0,t9=0,ra=0,sp=stack_start+0xe00,gp=0x23daf0;
    u64 hi=0,lo=0,hi1=0,lo1=0;
    u64 read(u32 p,unsigned width) const {
        u64 result=0;
        if(p>=stack_start){
            if(p-stack_start>stack.size()-width)throw std::out_of_range("Native scalar stack read");
            for(unsigned i=0;i<width;++i)result|=u64(stack[p-stack_start+i])<<(8*i);
        }else{
            const auto bytes=m.bytes(p,width);
            for(unsigned i=0;i<width;++i)result|=u64(bytes[i])<<(8*i);
        }
        return result;
    }
    void write(u32 p,u64 value,unsigned width){
        if(p>=stack_start){
            if(p-stack_start>stack.size()-width)throw std::out_of_range("Native scalar stack write");
            for(unsigned i=0;i<width;++i)stack[p-stack_start+i]=std::uint8_t(value>>(8*i));
        }else{
            std::array<std::uint8_t,8> bytes{};
            for(unsigned i=0;i<width;++i)bytes[i]=std::uint8_t(value>>(8*i));
            m.write_bytes(p,std::span(bytes).first(width));
        }
    }
    u64 ld(u32 p) const{return read(p,8);}
    u64 lw(u32 p) const{return sx32(read(p,4));}
    u64 lhu(u32 p) const{return read(p,2);}
    u64 lbu(u32 p) const{return read(p,1);}
    u64 lb(u32 p) const{return u64(i64(std::bit_cast<std::int8_t>(std::uint8_t(read(p,1)))));}
    void sw(u32 p,u64 value){write(p,value,4);}
    void sd(u32 p,u64 value){write(p,value,8);}
    u64 product(u64 left,u64 right,bool accumulate){
        const u64 prior=accumulate?(u64(u32(hi))<<32)|u32(lo):0;
        const u64 result=prior+u64(i64(s32(left))*s32(right));
        hi=sx32(result>>32);lo=sx32(result);return lo;
    }
    void sb(u32 p,u64 value){write(p,value,1);}
    void sh(u32 p,u64 value){write(p,value,2);}
};
}
