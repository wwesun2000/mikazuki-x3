#include "actor_choice.hpp"
#include "choice_pipeline.hpp"
#include "control_transfer.hpp"
#include "source_libc.hpp"
#include "guest_memory.hpp"
#include <algorithm>
#include <array>
#include <bit>

namespace kx3 {
namespace {
using u32=std::uint32_t;
using u64=std::uint64_t;
constexpr u32 manager_cell=0x235e40,panel=0x2387a8,descriptor=0x22c378,done_pointer=0x2366c8;
constexpr u32 phase=0x2366c0,alpha=0x2366cc,focus_cell=0x2366fc,cards=0x23e988,light=0x23e8b0;
constexpr u32 result_cell=0x2387c8,previous=0x2387c0,key_count=0x236704,last_key=0x236708;
struct Route {u32 selector,label;};

std::int32_t variable(GuestMemory& m,u32 index){
    return std::bit_cast<std::int32_t>(u32(run_scenario_return(m,0x100ec8,index,0,nullptr)));
}
std::int32_t story_phase(GuestMemory& m){ // 14BC98: signed SLTI with 9, then MOVZ caps the upper end at 8.
    return std::min<std::int32_t>(8,variable(m,4));
}
bool available(GuestMemory& m,u32 actor){ // 14BCC0/14BD18
    return actor<4 && m.read_u32(0x22c2b4+20*story_phase(m)+4*actor);
}
void format_stack(GuestMemory& m,u32 manager,bool push){
    const auto stack=m.read_u32(manager+0x2a0);
    if(!stack)throw std::runtime_error("Original actor context needs format stack 0x00116370");
    const auto depth=m.read_u32(stack+4),size=m.read_u32(stack+8),data=m.read_u32(stack+12);
    if(push){
        if(depth>=m.read_u32(stack))throw std::runtime_error("Original format stack overflow 0x001163E8");
        (void)source_memcpy(m,data+size*depth,manager+0x294,size);
        m.write_u32(stack+4,depth+1);
    }else{
        if(!depth)throw std::runtime_error("Original format stack underflow 0x00116470");
        m.write_u32(stack+4,depth-1);
        (void)source_memcpy(m,manager+0x294,data+size*(depth-1),size);
    }
}
void initialize_portraits(GuestMemory& m){ // Descriptor callback 14B120.
    const auto row=story_phase(m);
    m.write_u32(key_count,0);m.write_u32(last_key,0);m.write_u32(alpha,0);
    m.write_u32(focus_cell,m.read_u32(0x22c2b0+20*row));
    for(u32 i=0;i<4;++i){
        m.write_u32(light+4*i,0);
        u32 table=0x22c2b4+row*20;
        if(row==7){
            const auto index=std::bit_cast<std::int16_t>(m.read_u16(0x236720+2*i));
            table=variable(m,u32(index))==1?0x22c354u:0x22c340u;
        }
        m.write_u32(cards+4*i,m.read_u32(table+4*i));
    }
    m.write_u32(previous,UINT32_MAX);
}
void initialize_panel(GuestMemory& m,u32 object){ // 135BD8 -> 14BD70 -> 149F00.
    m.write_u32(0x23670c,4);m.write_u32(0x2387c4,4);m.write_u32(phase,0);m.write_u32(phase+4,0);
    m.write_u32(done_pointer,object);m.write_u32(result_cell,object+4);
    m.write_u32(panel+4,0);m.write_u32(panel,descriptor);initialize_portraits(m);
    // 145388 requests the descriptor's raw PANEL/hrsel.dat. The host renderer
    // owns its immutable original file bytes in place of the EE's DMA cache.
    m.write_u32(panel+4,m.read_u32(descriptor+20));
}
void caption(GuestMemory& m,u32 actor,u32 x,u32 y,ExecutionServices* services){ // 14BC48 -> 119C60
    const auto mgr=m.read_u32(manager_cell),object=m.read_u32(mgr+0x1c),script=m.read_u32(mgr+0x38);
    if(!m.read_u32(object+0x50))return;
    const auto name=m.read_u32(0x205cf8+actor*4);
    m.write_u32(mgr+0x40,m.read_u32(0x235f58));
    const auto selector=invoke_recovered(m,0x10f9b0,script,name);
    (void)invoke_recovered(m,0x10db48,script,selector,name);
    (void)invoke_recovered(m,0x1114f8,mgr,0,0,0,services);
    (void)invoke_recovered(m,0x16a950,m.read_u32(mgr+0x3c),x,y,0,services);
}
void request(GuestMemory& m,u32 callback,u32 a=0,u32 b=0,u32 c=0){ // 135030
    const auto n=m.read_u32(0x235fa8);
    if(n==16)return;
    if(n>16)throw std::runtime_error("Invalid 0x00135030 panel callback count");
    m.write_u32(0x23a6e0+4*n,callback);
    const auto record=0x23a720+16*n;
    m.write_u32(record,a);m.write_u32(record+4,b);m.write_u32(record+8,c);m.write_u32(record+12,0);
    m.write_u32(0x235fa8,n+1);
}
void dispatch_requests(GuestMemory& m,ExecutionServices* s){ // 135080, after the panel draw.
    const auto mgr=m.read_u32(manager_cell);
    for(u32 i=0;i<m.read_u32(0x235fa8);++i){
        if(i>=16)throw std::runtime_error("Invalid 0x00135080 callback count");
        const auto p=0x23a720+16*i,fn=m.read_u32(0x23a6e0+4*i);
        if(fn==0x14bc48)caption(m,m.read_u32(p),m.read_u32(p+4),m.read_u32(p+8),s);
        else if(fn==0x14a048)m.write_u32(m.read_u32(p),m.read_u32(p+4));
        else if(fn==0x14a080)(void)invoke_recovered(m,0x16b8a0,m.read_u32(0x235e20),m.read_u32(mgr+0x3c),0,0,s);
        else (void)invoke_recovered(m,fn,m.read_u32(p),m.read_u32(p+4),m.read_u32(p+8),m.read_u32(p+12),s);
    }
    m.write_u32(0x235fa8,0);
}
u64 enter(GuestMemory& m,ExecutionServices* s){ // 12E180 / 119A18
    const auto manager=m.read_u32(manager_cell),script=m.read_u32(manager+0x38),object=m.read_u32(manager+0x1c);
    auto read=[&](u32 e,u32 n=0){return u32(invoke_recovered(m,e,script,n));};
    auto route=[&](){const auto selector=read(0x10d5d8,1);return Route{selector,read(0x10d680)};};
    (void)read(0x10d638);
    std::array<Route,7> routes{};
    const auto n=read(0x10d5d8,1);
    if(n>6)throw std::runtime_error("Invalid original 119A18 actor selection table extent");
    for(u32 i=0;i<n;++i)routes[i]=route();
    const auto fallback=route();
    m.write_u16(0x238af0+2*0x19b,m.read_u16(0x238af8));
    (void)invoke_recovered(m,0x1ac690,0,0,0,0,s);
    if(m.read_u32(manager+0x808)){
        u32 total=0;
        for(u32 i=0;i<n;++i)if(available(m,i))routes[total++]=routes[i];
        routes[total++]=fallback;
        std::array<u32,7> unread{};u32 remaining=0;
        for(u32 i=0;i<total;++i)
            if(!invoke_recovered(m,0x10f018,script,routes[i].selector,routes[i].label))unread[remaining++]=i;
        const auto bound=remaining?remaining:total;
        const auto random=bound==1?0:u32(invoke_recovered(m,0x17aa28,0,bound-1,0,0,s));
        const auto selected=routes[remaining?unread[random]:random];
        (void)invoke_recovered(m,0x10d868,script,selected.selector,selected.label,0,s);
        return 0;
    }
    m.write_u32(object+8,m.read_u32(manager+0x40));format_stack(m,manager,true);
    (void)invoke_recovered(m,0x111550,manager,0);
    m.write_u32(manager+0x40,m.read_u32(0x235f54));
    for(u32 i=0;i<n;++i){m.write_u32(object+12+8*i,routes[i].selector);m.write_u32(object+16+8*i,routes[i].label);}
    m.write_u32(object+60,fallback.selector);m.write_u32(object+64,fallback.label);
    m.write_u32(object+4,UINT32_MAX);m.write_u32(object,0);
    initialize_panel(m,object);(void)invoke_recovered(m,0x1114f8,manager,0,0,0,s);
    m.write_u32(object+80,1);m.write_u32(object+68,read(0x10d740));m.write_u32(object+72,read(0x10d748));
    m.write_u32(object+76,read(0x10d610));return 1;
}
}
ActorChoiceView actor_choice_view(const GuestMemory& m,u32 manager){
    ActorChoiceView v;
    const auto object=m.read_u32(manager+0x1c);
    if(!object || !m.read_u32(object+80) || m.read_u32(panel)!=descriptor)return v;
    v.open=true;v.focus=m.read_u32(focus_cell);v.opacity=m.read_u32(alpha);
    v.accepting=!m.read_u32(object) && !m.read_u32(phase) && v.opacity==128;
    for(u32 i=0;i<4;++i){v.portrait[i]=m.read_u32(cards+4*i);v.highlight[i]=m.read_u32(light+4*i);}
    return v;
}
void advance_actor_panel(GuestMemory& m,ExecutionServices* s){
    if(m.read_u32(panel)!=descriptor)return;
    const auto done=m.read_u32(done_pointer);
    if(m.read_u32(done))return;
    const bool closing=m.read_u32(phase)!=0;
    const auto intensity=m.read_u32(alpha);
    if(closing && intensity<=2){
        m.write_u32(alpha,0);m.write_u32(panel,0);request(m,0x14a048,done,1);dispatch_requests(m,s);return;
    }
    m.write_u32(alpha,closing?intensity-2:std::min(128u,intensity+4));
    const bool can=!closing && m.read_u32(alpha)==128;
    if(!invoke_recovered(m,0x15fec8,0x238700,0x238702,0,0,s)){
        m.write_u16(0x238700,0);m.write_u16(0x238702,0);
    }
    const auto held=m.read_u16(0x238700);auto edges=m.read_u16(0x238702);
    m.write_u32(key_count,(!held || u32(held)==m.read_u32(last_key))?m.read_u32(key_count)+1:0);
    m.write_u32(last_key,held);
    const auto old=m.read_u32(focus_cell);
    if(old>=4)throw std::runtime_error("Invalid 14B2A0 original actor focus");
    auto focus=old;
    if(can){
        if(edges&0x8020)focus=(old+1)%4;else if(edges&0x80)focus=(old+3)%4;
        const int point=s && s->choice_input?s->choice_input->actor_index:-1;
        if(point>=0 && point<4){
            focus=u32(point);if(s->choice_input->actor_confirm)edges|=0x2000;
        }
    }
    auto sound=[&](u32 id){(void)invoke_recovered(m,0x1b15f0,id,60,0,0,s);};
    if(focus!=old){m.write_u32(focus_cell,focus);sound(4);m.write_u32(focus_cell+4,0);}
    const auto portrait=m.read_u32(cards+4*focus);
    if(focus!=m.read_u32(previous)){
        m.write_u32(previous,focus);
        request(m,0x14bc48,portrait?focus:5,112*focus+(portrait?160-m.read_u32(0x22c230+4*focus):133),348);
    }
    m.write_u32(focus_cell+4,m.read_u32(focus_cell+4)+1);
    for(u32 i=0;i<4;++i){
        const auto value=m.read_u32(light+4*i);
        m.write_u32(light+4*i,i==focus?std::min(127u,value+8):(value<4?0:value-4));
    }
    // 14B484..14BAEC draws source textures; ActorChoiceView exposes the same
    // atlas indices, 2-pass lighting and fade coefficients to a native renderer.
    if(can && (edges&0x6500)){
        if((edges&0x4400) || !portrait)sound(6);
        else {sound(2);request(m,0x14a048,m.read_u32(result_cell),focus);request(m,0x14a080);m.write_u32(phase,1);}
    }
    dispatch_requests(m,s);
}
bool has_actor_choice(u32 entry){
    switch(entry){
    case 0x12e180:case 0x14b120:case 0x14bc98:case 0x14bd18:case 0x14bcc0:case 0x120900:case 0x119b60:
    case 0x120b28:case 0x121370:case 0x122e18:case 0x128a28:case 0x12f9a8:case 0x1324e8:return true;
    default:return false;
    }
}
u64 invoke_actor_choice(GuestMemory& m,u32 entry,u32 self,u64 a1,ExecutionServices* s){
    if(entry==0x12e180)return enter(m,s);
    if(entry==0x14b120){initialize_portraits(m);return 0;}
    if(entry==0x14bc98)return u64(std::int64_t(story_phase(m)));
    if(entry==0x14bd18 || entry==0x14bcc0)return available(m,self);
    const auto manager=m.read_u32(manager_cell),script=m.read_u32(manager+0x38);
    if(entry==0x122e18 || entry==0x128a28)
        return invoke_recovered(m,entry==0x122e18?0x122bf0:0x1287d0,self,a1,0,0,s);
    if(entry==0x12f9a8){
        (void)invoke_recovered(m,0x12f6c0,self,0,0,0,s);
        (void)invoke_recovered(m,0x12f1a8,self,0,0,0,s);return 0;
    }
    if(entry==0x1324e8){
        m.write_u32(manager+0x40,m.read_u32(0x235f54));return 0;
    }
    if(entry==0x120900){
        const auto first=m.read_u32(u32(a1)+24),second=m.read_u32(u32(a1)+28);
        return !invoke_recovered(m,m.read_u32(first+200)?0x119820:0x119b60,
                                 m.read_u32(first+200)?first:second,0,0,0,s);
    }
    if(entry==0x119b60){
        if(!m.read_u32(self))return 0;
        const u32 selected=m.read_u32(self+4);
        if(selected!=UINT32_MAX && selected>=6)throw std::runtime_error("Invalid original 119B60 target index");
        const auto offset=selected==UINT32_MAX?60:12+8*selected;
        (void)invoke_recovered(m,0x1114f8,manager,0,0,0,s);
        const auto target=m.read_u32(self+offset),label=m.read_u32(self+offset+4);
        (void)invoke_recovered(m,0x10daf0,script,m.read_u32(self+68),m.read_u32(self+72));
        (void)invoke_recovered(m,0x10d700,script,m.read_u32(self+76));
        (void)invoke_recovered(m,0x10d868,script,target,label,selected==UINT32_MAX,s);
        format_stack(m,manager,false);m.write_u32(manager+64,m.read_u32(self+8));m.write_u32(self+80,0);return 1;
    }
    if(entry==0x120b28)return invoke_recovered(m,0x121370,self+m.read_u32(m.read_u32(self)-12),a1,0,0,s);
    if(entry==0x121370){
        const auto sc=m.read_u32(u32(a1)+0x38);
        const auto offset=invoke_recovered(m,0x10d610,sc);
        const auto opcode=u32(invoke_recovered(m,0x10d5d8,sc,1));
        for(u32 i=0;i<10;++i){
            if(m.read_u32(0x2061d8+4*i)!=opcode)continue;
            const auto fn=m.read_u32(m.read_u32(self));
            const auto handler=m.read_u32(u32(a1)+0x5c+4*opcode);
            return invoke_recovered(m,fn,self,handler,offset,opcode,s);
        }
        return invoke_recovered(m,0x111738,u32(a1),offset,opcode,0,s);
    }
    throw std::invalid_argument("Unknown actor panel source entry");
}
}
