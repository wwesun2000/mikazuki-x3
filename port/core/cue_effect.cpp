#include "cue_effect.hpp"
#include "expandband_recomp.hpp"
#include "gradefilter.hpp"
#include "expandblur.hpp"
#include "screen_zoom.hpp"
#include "screen_shake.hpp"
#include "field_feedback.hpp"
#include "masked_feedback.hpp"
#include "captured_blur.hpp"
#include "screen_ripple.hpp"
#include "particle_effect.hpp"
#include "depth_particles.hpp"
#include "mime_effect.hpp"
#include "guest_memory.hpp"
#include "recovered.hpp"
#include "session_clock.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <sstream>

namespace kx3 {
namespace {
using u32=std::uint32_t;
using i32=std::int32_t;
constexpr u32 table=0x2388bc;
float real(GuestMemory& m,u32 p){return std::bit_cast<float>(m.read_u32(p));}
void store(GuestMemory& m,u32 p,float v){m.write_u32(p,std::bit_cast<u32>(v));}
[[noreturn]] void unsupported(u32 source){
    std::ostringstream message;message<<"Unrecovered ScenePack effect source 0x"<<std::hex<<source;
    throw std::runtime_error(message.str());
}
u32 big(GuestMemory& m,u32 p){ // 111580
    return u32(m.read_u8(p))<<24 | u32(m.read_u8(p+1))<<16 | u32(m.read_u8(p+2))<<8 | m.read_u8(p+3);
}
bool suspended(GuestMemory& m,u32 owner){
    const auto p=m.read_u32(owner+32);return m.read_u32(p+4) && m.read_u32(p+8);
}
u32 record_for(GuestMemory& m,u32 records,u32 id){
    u32 i=0;
    while(i<10 && (!m.read_u32(records+100*i) || m.read_u32(records+100*i+4)!=id))++i;
    return records+100*i;
}
void remove_effect(GuestMemory& m,u32 records,u32 id){ // 1143B0 -> 179D48
    const auto pool=m.read_u32(table);
    for(u32 i=0;i<10;++i){
        const auto row=records+100*i;
        if(!m.read_u32(row)||m.read_u32(row+4)!=id)continue;
        m.write_u32(row,0);m.write_u32(row+12,0);
        const auto handle=m.read_u32(row+8);
        for(u32 j=0;j<37;++j){
            const auto task=pool+48*j;
            if(task!=handle || !m.read_u32(task))continue;
            const auto cleanup=m.read_u32(task+32);
            if(cleanup==0x1848b8)release_expandband(m,task);
            else if(cleanup==0x1819b8)release_gradefilter(m,task);
            else if(cleanup==0x183240)release_expandblur(m,task);
            else if(cleanup==0x1826a0 || cleanup==0x1829f0)release_screen_zoom(m,task);
            else if(cleanup==0x1822f0)release_screen_shake(m,task);
            else if(cleanup==0x17ea98)release_field_feedback(m,task);
            else if(cleanup==0x17f658)release_masked_feedback(m,task);
            else if(cleanup==0x17fe98)release_captured_blur(m,task);
            else if(cleanup==0x181f78)release_screen_ripple(m,task);
            else if(cleanup==0x1840a0)release_depth_particles(m,task);
            else if(cleanup && cleanup!=0x181290 && cleanup!=0x186fc0 && cleanup!=0x183808 && cleanup!=0x17e558 && cleanup!=0x17ca80)unsupported(cleanup);
            m.write_u32(task,0);m.write_u32(task+4,0);
        }
    }
}
}
u32 reserve_mode_zero_task(GuestMemory& m){
    // 179B58 mode zero, table cells 13..22, independent of mode-two fades.
    const auto pool=m.read_u32(table);
    if(!pool)throw std::runtime_error("Original ScenePack effect task pool unavailable");
    for(u32 i=0;i<10;++i){
        const auto task=pool+(13+i)*48;
        if(m.read_u32(task))continue;
        for(u32 off=0;off<48;off+=4)m.write_u32(task+off,0);
        m.write_u32(task,1);
        return task;
    }
    throw std::runtime_error("179B58 mode-zero task pool exhausted");
}
u32 large_effect_payload(const GuestMemory& m,u32 task,u32 bytes){
    const auto first=m.read_u32(table)+13*48;
    constexpr u32 stride=0x16000;
    if(task<first || task>=first+10*48 || (task-first)%48 || bytes>stride)
        throw std::runtime_error("Original effect allocation exceeds its reserved task slot");
    return 0x1410000+((task-first)/48)*stride;
}
namespace {
u32 allocate_task(GuestMemory& m,u32 heap){
    if(!heap)throw std::runtime_error("Original ScenePack effect task heap unavailable");
    const auto task=reserve_mode_zero_task(m),pool=m.read_u32(table);
    m.write_u32(task+44,heap+0x200+64*((task-pool)/48-13));
    return task;
}
u32 create(GuestMemory& m,u32 factory,std::span<const u32> args,ExecutionServices* services){
    if(factory==0x1812a8)return create_gradefilter(m,services?services->screen_task_heap:0,args);
    if(factory==0x182a08 || factory==0x182aa0)return create_expandblur(m,services?services->screen_task_heap:0,factory,args);
    if(factory==0x182308 || factory==0x1826b8)return create_screen_zoom(m,services?services->screen_task_heap:0,factory,args);
    if(factory==0x181f90)return create_screen_shake(m,services?services->screen_task_heap:0,args);
    if(factory==0x17e570)return create_field_feedback(m,services?services->screen_task_heap:0,args);
    if(factory==0x17f008)return create_masked_feedback(m,services?services->screen_task_heap:0,args);
    if(factory==0x17f670)return create_captured_blur(m,args);
    if(factory==0x1819d0)return create_screen_ripple(m,args);
    if(factory==0x183820)return create_depth_particles(m,args,services);
    if(factory==0x184690){
        if(args.size()!=1)throw std::runtime_error("Invalid effect_expandband.c source arguments");
        return create_expandband(m,services?services->screen_task_heap:0,args[0]);
    }
    if(factory==0x17ba58)return create_mime_effect(m,args,services);
    if(factory==0x17e0c0 || factory==0x17e0e8){
        const bool fixed=factory==0x17e0c0;
        if(args.size()!=(fixed?6:7))throw std::runtime_error("Invalid effect_flash.c source arguments");
        const auto task=allocate_task(m,services?services->screen_task_heap:0),data=m.read_u32(task+44);
        m.write_u32(task+20,0x17e288);m.write_u32(task+24,0x17e3d8);m.write_u32(task+32,0x17e558);
        const auto ramp=std::bit_cast<i32>(args[0]),exit_ticks=std::bit_cast<i32>(args[2]?args[2]:1);
        const auto minimum=fixed?64u:args[6];
        const float full=real(m,0x2373a8);
        m.write_u32(data,ramp?0:(args[1]?1:2));m.write_u32(data+4,args[1]);
        store(m,data+8,ramp?full:float(std::bit_cast<i32>(minimum)));store(m,data+12,ramp?full/float(ramp):full);
        store(m,data+16,full/float(exit_ticks));
        for(u32 c=0;c<3;++c)m.write_u32(data+20+4*c,args[3+c]);
        m.write_u32(data+32,std::bit_cast<u32>(exit_ticks));m.write_u32(data+36,minimum);return task;
    }
    if(factory==0x183258) {
        if(args.size()!=2)throw std::runtime_error("Invalid 183258 particle arguments");
        return create_snow_particles(m,args[0],args[1],services);
    }
    if(factory==0x186ad0){ // 186AD0 -> 186BC0 and three callback setters.
        if(args.size()!=6)throw std::runtime_error("Invalid 186AD0 ABI");
        const auto task=allocate_task(m,services?services->screen_task_heap:0),data=m.read_u32(task+44);
        m.write_u32(task+16,1);m.write_u32(task+20,0x186cf0);
        m.write_u32(task+24,0x186da0);m.write_u32(task+32,0x186fc0);
        const auto low=std::bit_cast<i32>(args[3]),high=std::max(low,std::bit_cast<i32>(args[4]));
        store(m,data+24,float(low));store(m,data+28,float(high));
        const auto start=source_random_range(m,float(low),float(high),services);
        for(u32 c=0;c<3;++c)m.write_u32(data+12+4*c,args[c]);
        store(m,data,start);store(m,data+4,start);
        store(m,data+32,real(m,0x237710)/float(std::max(1,std::bit_cast<i32>(args[5]))));
        return task;
    }
    if(factory!=0x180eb0)unsupported(factory);
    if(args.size()!=4)throw std::runtime_error("Invalid 180EB0 ABI");
    const auto task=allocate_task(m,services?services->screen_task_heap:0);
    const auto data=m.read_u32(task+44);
    m.write_u32(task+20,0x181020);m.write_u32(task+24,0x181110);m.write_u32(task+28,0x1811d0);
    m.write_u32(task+32,0x181290);
    const auto duration=std::bit_cast<i32>(args[0]);
    const float start=real(m,0x237468);
    for(u32 c=0;c<3;++c){
        const float goal=float(std::bit_cast<i32>(args[c+1]));
        store(m,data+4*c,goal);
        store(m,data+12+4*c,duration?(goal-start)/float(duration):goal);
        store(m,data+24+4*c,duration?start:goal);
    }
    m.write_u32(data+36,args[0]);return task;
}
}
bool retained_cue_effect(GuestMemory& m,u32 owner,u32 blob){
    const auto records=owner+0x330,id=big(m,blob);
    const auto old=record_for(m,records,id);
    return m.read_u32(records+0x3ec) && m.read_u32(records+0x3e8) && old!=records+1000 && m.read_u32(old+12);
}
void cue_effect_on(GuestMemory& m,u32 owner,u32 blob,u32 bytes,ExecutionServices* services){
    if(bytes<5)throw std::runtime_error("Short ScenePack EFFECT_ON parameters");
    const auto records=owner+0x330,id=big(m,blob),count=u32(m.read_u8(blob+4));
    if(count>9 || bytes!=5+4*count || id>=0x300)throw std::runtime_error("Invalid original effect arguments");
    const auto old=record_for(m,records,id);
    if(suspended(m,owner) || old!=records+1000)return;
    for(u32 i=0;i<10;++i){
        const auto row=records+100*i;if(m.read_u32(row))continue;
        m.write_u32(row+4,id);m.write_u32(row,1);m.write_u32(row+12,0);
        std::array<u32,9> args{};
        for(u32 j=0;j<count;++j)args[j]=big(m,blob+5+4*j);
        const auto handle=create(m,m.read_u32(0x205640+id*8),std::span(args).first(count),services);
        m.write_u32(row+8,handle);m.write_u32(row+16,count);
        bool zero_first=false;
        for(u32 j=0;j<19;++j)zero_first|=m.read_u8(0x205c98+j)==id; // 114788 -> 1144A8
        for(u32 j=0;j<count;++j)m.write_u32(row+20+4*j,(!j && zero_first)?0:m.read_u32(blob+5+4*j));
        return;
    }
}
void cue_effect_off(GuestMemory& m,u32 owner,u32 blob,u32 bytes){
    if(bytes!=4)throw std::runtime_error("Invalid original EFFECT_OFF parameters");
    remove_effect(m,owner+0x330,big(m,blob));
}
void cue_effect_change(GuestMemory& m,u32 owner,u32 blob,u32 bytes){ // 10C578 -> 1147B8 -> 114698
    if(bytes<5)throw std::runtime_error("Short ScenePack EFFECT_CHANGE");
    const auto count=u32(m.read_u8(blob+4));
    if(count>9 || bytes!=5+count*4)throw std::runtime_error("Invalid source EFFECT_CHANGE arguments");
    std::array<u32,9> args{};
    for(u32 i=0;i<count;++i)args[i]=big(m,blob+5+4*i);
    const auto row=record_for(m,owner+0x330,big(m,blob)),task=m.read_u32(row+8);
    const auto change=m.read_u32(task+28);if(!change)return;
    if(change==0x181858){change_gradefilter(m,task,std::span(args).first(count));return;}
    if(change==0x17c960){change_mime_effect(m,task,std::span(args).first(count));return;}
    if(change!=0x1811d0)unsupported(change);
    if(count!=4)throw std::runtime_error("Invalid 1811D0 ABI");
    const auto data=m.read_u32(task+44);
    const auto ticks=std::bit_cast<i32>(args[0]);
    for(u32 c=0;c<3;++c){
        const auto goal=float(std::bit_cast<i32>(args[c+1]));
        store(m,data+4*c,goal);
        if(ticks)store(m,data+12+4*c,(goal-real(m,data+24+4*c))/float(ticks));
        else store(m,data+24+4*c,goal);
    }
    m.write_u32(data+36,args[0]);m.write_u32(task+16,0); // source clears completion, including for zero duration
}
bool cue_effect_busy(GuestMemory& m,u32 owner,u32 id){
    if(suspended(m,owner))return false;
    const auto row=record_for(m,owner+0x330,id);
    return !m.read_u32(m.read_u32(row+8)+16); // 1144E0 includes the after-table read on a miss.
}
void clear_cue_effects(GuestMemory& m,u32 owner){ // 114348
    const auto records=owner+0x330;
    for(u32 i=0;i<10;++i)if(m.read_u32(records+i*100))remove_effect(m,records,m.read_u32(records+i*100+4));
}
void tick_cue_effects(GuestMemory& m,u32 heap,ExecutionServices* services){
    const auto pool=m.read_u32(table);if(!pool)return;
    for(u32 i=0;i<10;++i){
        const auto task=pool+(13+i)*48;if(!m.read_u32(task) || m.read_u32(task+36))continue;
        const auto update=m.read_u32(task+20),data=m.read_u32(task+44);
        if(!update)continue; // 17E288 removes its update callback after its final draw state.
        if(update==0x17c498 || update==0x17c598){update_mime_effect(m,task,services);continue;}
        if(update==0x17e288){update_flash_effect(m,task);continue;}
        if(update==0x1833f8){update_snow_particles(m,task,services);continue;}
        if(update==0x183b10){update_depth_particles(m,task,services);continue;}
        if(update==0x182078){update_screen_shake(m,task,services);continue;}
        if(update==0x17e698){update_field_feedback(m,task);continue;}
        if(update==0x17f1a8){update_masked_feedback(m,task);continue;}
        if(update==0x181bc8){update_screen_ripple(m,task);continue;}
        if(update==0x1824c8 || update==0x182870){
            update_screen_zoom(m,task,update);continue;
        }
        if(update==0x182d58 || update==0x182e90 || update==0x182f70){
            if(data!=blur_payload(heap,i))throw std::runtime_error("Unexpected expand blur task allocation");
            update_expandblur(m,task,update);continue;
        }
        if(update==0x1814c0){
            if(data!=heap+0x500+80*i)throw std::runtime_error("Unexpected grade filter task allocation");
            update_gradefilter(m,task);continue;
        }
        if(data!=heap+0x200+64*i)throw std::runtime_error("Unexpected original ScenePack task heap");
        if(update==0x184760){update_expandband(m,task);continue;}
        if(update==0x186cf0){
            const float value=real(m,data);
            store(m,data,value+(real(m,data+4)-value)*real(m,data+32));
            store(m,data+4,source_random_range(m,real(m,data+24),real(m,data+28),services));
            continue;
        }
        if(update!=0x181020)unsupported(update);
        for(u32 c=0;c<3;++c){
            const float target=real(m,data+4*c),step=real(m,data+12+4*c),next=real(m,data+24+4*c)+step;
            store(m,data+24+4*c,step>0?std::min(target,next):std::max(target,next));
        }
        const auto left=std::bit_cast<i32>(m.read_u32(data+36)-1);
        m.write_u32(data+36,left>0?u32(left):0);
        if(left<=0)m.write_u32(task+16,1);
    }
    // 179B58(3) owns slots 23..32, after the mode-zero effects. Name-entry
    // tasks in this range retain their separate original input/update path.
    for(u32 i=23;i<=32;++i){
        const auto task=pool+i*48;
        if(m.read_u32(task) && !m.read_u32(task+36) && m.read_u32(task+20)==0x17f7f0)
            update_captured_blur(m,task);
    }
}
void update_flash_effect(GuestMemory& m,u32 task){
    const auto data=m.read_u32(task+44),state=m.read_u32(data);
    if(state==0){
        const float next=real(m,data+8)-real(m,data+12),minimum=float(std::bit_cast<i32>(m.read_u32(data+36)));
        if(next<=minimum){store(m,data+8,minimum);m.write_u32(data,std::bit_cast<i32>(m.read_u32(data+4))>0?1:2);}
        else store(m,data+8,next);
    }else if(state==1){
        const auto left=m.read_u32(data+4)-1;m.write_u32(data+4,left);
        if(std::bit_cast<i32>(left)<=0)m.write_u32(data,2);
    }else if(state==2){
        const auto step=real(m,data+16),value=real(m,data+8),upper=real(m,0x2373ac);
        const bool exponential=step<=0;
        const float next=exponential?value+(upper-value)/float(std::bit_cast<i32>(0u-m.read_u32(data+32))):value+step;
        const bool done=next>=(exponential?real(m,0x2373b0):upper);
        store(m,data+8,done && !exponential?upper:next);
        if(done){m.write_u32(task+16,1);m.write_u32(task+20,0);}
    }
}
}
