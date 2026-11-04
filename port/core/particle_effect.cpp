#include "particle_effect.hpp"
#include "cue_effect.hpp"
#include "guest_memory.hpp"
#include "session_clock.hpp"
#include <bit>
#include <cmath>
#include <stdexcept>

namespace kx3 {
namespace {
using u32=std::uint32_t;
using i32=std::int32_t;
constexpr u32 heap=0x1410000,stride=0x16000;
float value(const GuestMemory& m,u32 address){return std::bit_cast<float>(m.read_u32(address));}
void store(GuestMemory& m,u32 address,float number){m.write_u32(address,std::bit_cast<u32>(number));}
u32 storage(const GuestMemory& m,u32 task,u32 count) {
    const auto first=m.read_u32(0x2388bc)+13*48;
    if(task<first || task>=first+10*48 || (task-first)%48 || count>(stride-20)/32)
        throw std::runtime_error("183258 particle allocation exceeds its reserved task slot");
    return heap+((task-first)/48)*stride;
}
}

u32 create_snow_particles(GuestMemory& m,u32 count,u32 wind,ExecutionServices* services) {
    const auto task=reserve_mode_zero_task(m);
    const auto data=storage(m,task,count);
    m.write_u32(task+16,1);m.write_u32(task+20,0x1833f8);m.write_u32(task+24,0x1836d8);
    m.write_u32(task+32,0x183808);m.write_u32(task+44,data);
    m.write_u32(data,count);m.write_u32(data+16,150);
    const auto speed=float(std::bit_cast<i32>(wind));
    for(u32 off:{4u,8u,12u})store(m,data+off,speed);
    auto rnd=[&](float a,float b){return source_random_range(m,a,b,services);};
    for(u32 i=0;i<count;++i) {
        const auto p=data+20+i*32;
        store(m,p,rnd(value(m,0x237534),value(m,0x237538)));
        store(m,p+4,rnd(0,value(m,0x23753c)));
        store(m,p+16,0);store(m,p+8,0);
        const auto vy=rnd(value(m,0x237530),value(m,0x237540));
        store(m,p+12,vy);store(m,p+20,vy);
        store(m,p+24,rnd(value(m,0x237530),value(m,0x237544)));
        store(m,p+28,rnd(value(m,0x237548),value(m,0x23754c)));
    }
    return task;
}

u32 snow_particle_count(const GuestMemory& m,u32 task) {
    const auto data=m.read_u32(task+44),count=m.read_u32(data);
    if(data!=storage(m,task,count))throw std::runtime_error("1833F8 invalid particle heap binding");
    return count;
}
void update_snow_particles(GuestMemory& m,u32 task,ExecutionServices* services) {
    const auto data=m.read_u32(task+44),count=snow_particle_count(m,task);
    const float wind=value(m,data+4),smoothing=value(m,0x237558),half=value(m,0x237550),two=value(m,0x237554);
    if(!std::isfinite(wind) || wind>=2147483648.0f || wind< -2147483648.0f)
        throw std::runtime_error("1833F8 invalid wind for EE CVT.W.S");
    const float integral_wind=float(i32(wind));
    auto rnd=[&](float a,float b){return source_random_range(m,a,b,services);};
    for(u32 i=0;i<count;++i) {
        const auto p=data+20+i*32;
        const float target=integral_wind*value(m,p+28),old_vx=value(m,p+8),old_vy=value(m,p+12);
        const float vx=old_vx+(target-old_vx)*smoothing;
        store(m,p+16,target);store(m,p+8,vx);
        float target_vy=value(m,p+20);
        if(old_vy<value(m,0x23755c) || old_vy>value(m,0x237560)) {
            const float acc=(old_vy*half)*rnd(0,1)+two; // 183694 ADDA.S followed by MADD.S.
            target_vy=-(acc+old_vy*half);
        }
        const float vy=old_vy+(target_vy-old_vy)*smoothing;
        const float y=value(m,p+4)+vy;
        store(m,p+12,vy);store(m,p+4,y);store(m,p,value(m,p)+vx);
        if(y>=value(m,0x237564) || y<value(m,0x23755c)) {
            store(m,p,rnd(value(m,0x237568),value(m,0x23756c)));
            store(m,p+4,rnd(0,1)>half?rnd(0,value(m,0x237570)):0);
            store(m,p+24,rnd(two,value(m,0x237574)));
            const float weight=rnd(value(m,0x237578),value(m,0x23757c));
            store(m,p+28,weight);store(m,p+16,integral_wind*weight);
            store(m,p+8,integral_wind*weight*value(m,0x237580));
            const float fresh=rnd(two,value(m,0x237560));store(m,p+12,fresh);store(m,p+20,fresh);
        }
    }
    const auto next=m.read_u32(data+16)-1;
    m.write_u32(data+16,next);
    if(std::bit_cast<i32>(next)<1) {
        m.write_u32(data+16,150);
        const float range=value(m,data+12);store(m,data+8,rnd(-range,range));
    }
    store(m,data+4,wind+(value(m,data+8)-wind)*value(m,0x237584));
}
}
