#include "record_scope.hpp"
#include "guest_memory.hpp"

namespace kx3 {
namespace {
using u32=std::uint32_t;
using u64=std::uint64_t;
constexpr u32 global_flag=0x235b3c; // Original gp - 0x7fb4.

void open_scope(GuestMemory& m,u32 script){ // 10F318
    const auto id=invoke_recovered(m,0x10d748,script);
    const auto record=u32(invoke_recovered(m,0x10eea0,script,id));
    if(!m.read_u32(script+0x150)){
        // 10E9D8's validity result is discarded. 10E8D8 always writes
        // both fields to the source caller's stack, even for sentinel links.
        const auto selector=m.read_u32(record+4)&31u;
        const auto previous=m.read_u32(record)&0x3fffu;
        const auto valid=invoke_recovered(m,0x10e708,script,previous,script+0x164,script+0x160);
        m.write_u32(script+0x15c,u32(valid));
        m.write_u32(script+0x154,selector);
        m.write_u32(script+0x158,previous);
    }
    m.write_u32(script+0x150,0);
    m.write_u32(script+0x14c,1);
}

void close_scope(GuestMemory& m,u32 script,u64 defer){ // 10F3C8
    m.write_u32(script+0x14c,0);
    m.write_u32(script+0x150,defer?1:0);
    if(defer)return; // Actual opcode 35 uses 1. No link is restored here.
    const auto record=u32(invoke_recovered(m,0x10e630,script,m.read_u32(script+0x158)));
    const bool valid=m.read_u32(script+0x15c)!=0;
    const auto label=valid?(m.read_u32(script+0x160)&0x3fffu):0x3fffu;
    const auto word1=m.read_u32(record+4);
    m.write_u32(record,(m.read_u32(record)&0xf0003fffu)|(label<<14));
    const auto selector=valid?(m.read_u32(script+0x164)&31u):31u;
    m.write_u32(record+4,(word1&~0x3e0u)|(selector<<5));
}
u64 apply(GuestMemory& m,u32 entry,u32 self,u64 a1){
    if(entry==0x132a08){
        if(a1!=0x34 && a1!=0x35)return 0;
        self=u32(invoke_recovered(m,0x10fb38,0))+0x32c;
        entry=a1==0x34?0x114aa0:0x114ae0;
        a1=1;
    }
    switch(entry){
    case 0x114aa0: case 0x114ae0:{
        const auto manager=u32(invoke_recovered(m,0x10fb38,0));
        const auto script=u32(invoke_recovered(m,0x1133a8,manager));
        const bool begin=entry==0x114aa0;
        m.write_u32(self,begin);
        if(begin)open_scope(m,script);else close_scope(m,script,a1);
        m.write_u32(global_flag,begin);
        return 0;
    }
    case 0x10f318:open_scope(m,self);return 0;
    case 0x10f3c8:close_scope(m,self,a1);return 0;
    default:throw std::invalid_argument("Unknown source record-scope function");
    }
}
}
bool has_record_scope(u32 entry) noexcept{
    return entry==0x132a08 || entry==0x114aa0 || entry==0x114ae0 || entry==0x10f318 || entry==0x10f3c8;
}
u64 invoke_record_scope(GuestMemory& m,u32 entry,u32 self,u64 a1){
    if(m.transaction_active())return apply(m,entry,self,a1);
    GuestMemory::Transaction tx(m);
    const auto result=apply(m,entry,self,a1);
    tx.commit();
    return result;
}
}
