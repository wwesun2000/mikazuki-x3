#include "screen_task.hpp"
#include "screen_slide.hpp"
#include "screen_wind.hpp"
#include "screen_wipes.hpp"
#include "screen_mesh.hpp"
#include "circlemask.hpp"
#include "guest_memory.hpp"
#include "recovered.hpp"
#include "native_scalar.hpp"
#include "screen_projection.hpp"
#include <array>
#include <bit>
#include <cmath>
#include <sstream>

namespace kx3 {
namespace {
using u32=std::uint32_t;
using i32=std::int32_t;
using u64=std::uint64_t;
constexpr u32 task_table=0x2388bc;
constexpr u32 page_flip_draw=0x192258;
float load(GuestMemory& m,u32 p){return std::bit_cast<float>(m.read_u32(p));}
void store(GuestMemory& m,u32 p,float v){m.write_u32(p,std::bit_cast<u32>(v));}
[[noreturn]] void unknown(u32 addr) {
    std::ostringstream s;s<<"Unrecovered screen task source function 0x"<<std::hex<<addr;
    throw std::runtime_error(s.str());
}
u32 manager(GuestMemory& m){return static_cast<u32>(invoke_recovered(m,0x10fb38,0));}

bool capture_pending(GuestMemory& m) { // 13D098.
    const auto tick=m.read_u32(0x20625c);
    if(m.read_u32(0x236104) || m.read_u32(0x236110)) {
        m.write_u32(0x236190,tick);m.write_u32(0x236100,tick);
        return true;
    }
    const auto last=m.read_u32(0x236100);
    if(!last || tick!=last+1)m.write_u32(0x236100,0);
    return false;
}

void retire_task(GuestMemory& m,u32 task) {
    const auto table=m.read_u32(task_table);
    for(u32 slot=0;slot<37;++slot) {
        const auto p=table+48*slot;
        if(m.read_u32(p) && p==task){m.write_u32(p+4,1);break;} // 179C80.
    }
}
void release_transition(GuestMemory& m){
    const u32 record=manager(m)+0x2d0; // 10C368 -> 111568 -> 113680.
    for(u32 off:{0u,8u,12u})m.write_u32(record+off,0);
}
void complete_task(GuestMemory& m,u32 task){retire_task(m,task);release_transition(m);}

using scalar::sx32;
using scalar::s32;
using scalar::s64;
struct TransitionRegisters : scalar::ScalarRegisters {
    using scalar::ScalarRegisters::ScalarRegisters;
    std::array<float,32> f{};
    bool condition=false;
    void leaf(u32 entry){
        switch(entry){
        case 0x1925f8:{
            const auto xy=screen_project_point(m,f[12]);
            sw(u32(a0),std::bit_cast<u32>(xy[0]));sw(u32(a0)+4,std::bit_cast<u32>(xy[1]));return;
        }
        case 0x192810:v0=screen_project_sector(m,f[12]);return;
        case 0x13d098:v0=screen_transition_service(m,entry,u32(a0));return;
        default:(void)screen_transition_service(m,entry,u32(a0));return;
        }
    }
};
#include "screen_transition_blocks.hpp"
bool transition_update(u32 entry){
    return entry==0x1928a8 || entry==0x192cb0 || entry==0x193008 || entry==0x193558;
}
void transition(GuestMemory& m,u32 entry,u32 task){
    TransitionRegisters r(m,nullptr);r.a0=task;
    switch(entry){
    case 0x1928a8:transition_1928a8(r);return;
    case 0x192cb0:transition_192cb0(r);return;
    case 0x193008:transition_193008(r);return;
    case 0x193558:transition_193558(r);return;
    default:unknown(entry);
    }
}

void update_effect(GuestMemory& m,u32 entry,u32 task) {
    const u32 data=m.read_u32(task+44);
    if(transition_update(entry)){transition(m,entry,task);return;}
    if(entry==0x17d3e0 || entry==0x17d418) {
        const float current=load(m,data+16),target=load(m,data+20);
        const float next=current+(target-current)*load(m,entry==0x17d3e0?0x237368:0x23736c);
        if(!std::isfinite(next) || next<0 || next>255)
            throw std::runtime_error("17D3E0 unsupported choice overlay level");
        store(m,data+16,next);m.write_u32(data+12,u32(next)); // EE CVT.W.S
        return;
    }
    if(entry!=0x18e978 && entry!=0x18ed90)unknown(entry);
    if(capture_pending(m)) {m.write_u32(task+40,1);return;}
    m.write_u32(task+40,0);
    if(entry==0x18e978) {
        const auto phase=m.read_u32(data);
        if(phase==0) {
            const float f=load(m,data+8)-load(m,data+12);
            store(m,data+8,f);
            if(f<=0){store(m,data+8,0);m.write_u32(data,1);}
        } else if(phase==1) {
            const u32 left=m.read_u32(data+4)-1;m.write_u32(data+4,left);
            if(std::bit_cast<i32>(left)<=0)m.write_u32(data,2);
        } else if(phase==2) {
            const float f=load(m,data+8)+load(m,data+16),max=load(m,0x237ba8);
            store(m,data+8,f);
            if(f>=max){store(m,data+8,max);complete_task(m,task);}
        }
    } else if(entry==0x18ed90) {
        const float f=load(m,data)-load(m,data+8), g=load(m,data+4)+load(m,data+8);
        const float cutoff=load(m,0x237bbc),max=load(m,0x237bb8);
        store(m,data,f<cutoff?0:f);store(m,data+4,g>=max?max:g);
        if(f<cutoff || g>=max)complete_task(m,task);
    } else unknown(entry);
}

u32 create_effect(GuestMemory& m,u32 cmd,std::span<const u32> args,u32 payloads) {
    if(!payloads || payloads%16 || payloads>GuestMemory::size-320)
        throw std::runtime_error("17A560 needs a reserved native task heap");
    const u32 target=m.read_u32(0x205640+8*cmd);
    if(target==0x1904d0)return screen_mesh::create(m,args);
    if(const auto* w=screen_wipe(target); w && target==w->factory)return create_screen_wipe(m,payloads,args,*w);
    if(target==0x18ef38)return create_screen_wind(m,payloads,args);
    if(target==0x18a710 || target==0x18aad8 || target==0x18b040)return create_screen_slide(m,payloads,args,target);
    if(target==0x193978)return create_circlemask(m,payloads,args);
    if(target!=0x18ed20 && target!=0x18ed58 && target!=0x18e840 && target!=0x192080)unknown(target);
    const bool fog=target==0x18e840;
    const bool panels=target==0x192080;
    if(args.size()!=(fog?6u:panels?2u:1u))throw std::runtime_error("113D28 unsupported effect ABI");
    const u32 pool=m.read_u32(task_table);
    const auto task=reserve_mode_two_task(m),slot=(task-pool)/48;
    const auto data=panels?payloads+0x1000+0x100*slot:payloads+32*slot;
    if(panels)(void)m.bytes(data,0xe8); // The separate native block avoids the legacy 32-byte effect slots.
    if(panels){
        u32 duration=args[0]?args[0]:1;const auto type=std::bit_cast<i32>(args[1]);
        constexpr std::array<u32,4> updates{0x1928a8,0x192cb0,0x193008,0x193558};
        m.write_u32(task+24,page_flip_draw);m.write_u32(task+32,0x192460);m.write_u32(task+44,data);
        if(type>=8 && type<=11){
            m.write_u32(task+20,updates[type-8]);
            m.write_u32(data,type==10?m.read_u32(0x237d4c):0);
            duration<<=type==8?0:type==11?2:1;
            if(!duration)throw std::runtime_error("192080 shifted duration reached EE zero divisor");
            store(m,data+4,load(m,0x237d50)/static_cast<float>(std::bit_cast<i32>(duration)));
        }else m.write_u32(data+4,0);
        return task;
    }
    if(target==0x18ed20)m.write_u32(task+12,1); // 18ED38 -> 179C60(task,1), after original glyph draw.
    m.write_u32(task+20,fog?0x18e978:0x18ed90);m.write_u32(task+24,fog?0x18ea98:0x18ee78);
    m.write_u32(task+32,fog?0x18ec50:0x18ef20);m.write_u32(task+44,data);
    if(fog) {
        const float max=load(m,0x237ba4);
        const auto interval=[](u32 x){return static_cast<float>(x?std::bit_cast<i32>(x):1);};
        m.write_u32(data,0);m.write_u32(data+4,args[1]);store(m,data+8,max);
        store(m,data+12,max/interval(args[0]));store(m,data+16,max/interval(args[2]));
        for(u32 i=0;i<3;++i)m.write_u32(data+20+4*i,args[i+3]);
    } else {
        if(!args[0])throw std::runtime_error("18EC68 zero-divisor EE FPU result needs validation");
        const auto max=load(m,0x237bb4);store(m,data,max);store(m,data+4,0);
        store(m,data+8,max/static_cast<float>(std::bit_cast<i32>(args[0])));
    }
    return task;
}
}

bool has_screen_task(u32 e) noexcept {
    return e==0x1266b8 || e==0x1269a8 || e==0x18e978 || e==0x18ed90 || e==0x13d098 ||
           e==0x17d3e0 || e==0x17d418 || transition_update(e);
}
u32 reserve_mode_two_task(GuestMemory& m){
    const auto pool=m.read_u32(task_table);
    if(!pool)throw std::runtime_error("179B58 task pool is uninitialized");
    for(u32 slot=0;slot<10;++slot){
        const auto task=pool+48*slot;
        if(m.read_u32(task))continue;
        for(u32 offset=0;offset<48;offset+=4)m.write_u32(task+offset,0);
        m.write_u32(task,1);m.write_u32(task+8,2);return task;
    }
    throw std::runtime_error("179B58 mode 2 task pool exhausted");
}
u32 screen_transition_service(GuestMemory& m,u32 entry,u32 task){
    switch(entry){
    case 0x13d098:return capture_pending(m);
    case 0x17a198:case 0x17a1a8:m.write_u32(task+40,entry==0x17a198);return 0;
    case 0x179c80:retire_task(m,task);return 0;
    case 0x10c368:release_transition(m);return 0;
    default:unknown(entry);
    }
}
u64 invoke_screen_task(GuestMemory& m,u32 entry,u32 self,u64 a1,ExecutionServices* services) {
    if(entry==0x18e978 || entry==0x18ed90 || entry==0x17d3e0 || entry==0x17d418 || transition_update(entry)){
        update_effect(m,entry,self);return 0;
    }
    if(entry==0x13d098)return capture_pending(m);
    const u32 owner=manager(m), record=owner+0x2d0,script=m.read_u32(owner+0x38);
    if(m.read_u32(record) || (entry==0x1269a8 && !m.read_u32(0x2062b8))) {
        (void)invoke_recovered(m,0x10d700,script,a1);
        return 1;
    }
    if(entry==0x1266b8)return 0;
    if(entry!=0x1269a8)unknown(entry);
    (void)invoke_recovered(m,0x10d638,script);
    auto read=[&](u32 n){return u32(invoke_recovered(m,0x10d5d8,script,n));};
    const auto cmd=read(4), argc=read(1);
    std::array<u32,9> args{};
    // 113610 -> 113D28 consumes the arguments even for the argc >= 10
    // branch, where the original dispatcher returns zero without a call.
    m.write_u32(record,1);m.write_u32(record+8,0);m.write_u32(record+12,0);
    for(u32 i=0;i<argc;++i){const u32 arg=read(4);if(i<args.size())args[i]=arg;}
    u32 handle=0;
    if(argc<=args.size()) {
        if(cmd>0x2ff)throw std::runtime_error("113D28 command table index exceeds source window");
        handle=create_effect(m,cmd,std::span(args).first(argc),services?services->screen_task_heap:0);
    }
    m.write_u32(record+4,handle);
    return 0;
}

void tick_screen_tasks(GuestMemory& m,u32 payloads) {
    const u32 pool=m.read_u32(task_table);
    if(!pool)return;
    // 179CC0 retires pending tasks before 179F30 runs the update callbacks.
    for(u32 i=0;i<13;++i){
        const auto task=pool+i*48;
        if(!m.read_u32(task) || !m.read_u32(task+4))continue;
        const auto cleanup=m.read_u32(task+32);
        if(cleanup==0x18aac0 || cleanup==0x18b028 || cleanup==0x18b580)release_screen_slide(m,task);
        else if(cleanup==0x1944a8)release_circlemask(m,task);
        else if(cleanup==0x18f718)release_screen_wind(m,task);
        else if(cleanup==0x191418)screen_mesh::release(m,task);
        else if(const auto* w=screen_wipe(cleanup); w && cleanup==w->release)advance_screen_wipe(m,task,cleanup);
        else if(cleanup!=0x18ec50 && cleanup!=0x18ef20 && cleanup!=0x17d4d0 && cleanup!=0x192460)unknown(cleanup);
        m.write_u32(task,0);m.write_u32(task+4,0);
    }
    for(u32 i=0;i<13;++i){
        const auto task=pool+i*48;
        if(!m.read_u32(task) || m.read_u32(task+36))continue;
        const auto draw=m.read_u32(task+24);
        const auto expected=draw==0x191168?screen_mesh::mesh_begin+i*screen_mesh::mesh_stride:
            (draw==0x18f3e8 || screen_wipe(draw))?wind_payload(i):draw==0x193cb8?circle_payload(payloads,i):draw==page_flip_draw?payloads+0x1000+0x100*i:payloads+32*i;
        if(i<10 && m.read_u32(task+44)!=expected)throw std::runtime_error("Unexpected visual task heap binding");
        const auto update=m.read_u32(task+20);
        if(update==0x18a890 || update==0x18ad18 || update==0x18b290)update_screen_slide(m,task);
        else if(update==0x18f230 || update==0x18f370)update_screen_wind(m,task);
        else if(update==0x190ed8)screen_mesh::update(m,task);
        else if(screen_wipe(update))advance_screen_wipe(m,task,update);
        else if(update==0x193bf0)update_circlemask(m,task);
        else if(update)update_effect(m,update,task);
    }
}
}
