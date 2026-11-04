#pragma once
#include "../core/guest_memory.hpp"
#include "../core/particle_effect.hpp"
#include "raster_frame.hpp"
#include <algorithm>
#include <bit>
#include <cmath>
#include <span>

namespace kx3::platform {
inline void check_particle_texture(const RasterFrame& frame,const GuestMemory& m,std::span<const std::uint8_t> texture){
    if(texture.size()!=1408 || m.read_u32(0x20c730)!=2 || frame.width!=640 || frame.height!=448 ||
       frame.rgba.size()!=640*448*4 || !std::equal(texture.begin(),texture.begin()+128,m.bytes(0x23a400,128).begin()))
        throw std::runtime_error("1769F0 sprite resource differs from original");
}
inline void draw_particle_sprite(RasterFrame& frame,std::span<const std::uint8_t> texture,
                                 float x,float y,float size,unsigned opacity,unsigned light){
    if(!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(size) || size<0)
        throw std::runtime_error("Invalid original particle projection");
    if(!size || !opacity)return;
    const auto edge=[](float value,int bound){return int(std::clamp(std::ceil(value-0.5f),0.f,float(bound)));};
    const int left=edge(x,640),right=edge(x+size,640),top=edge(y,448),bottom=edge(y+size,448);
    for(int sy=top;sy<bottom;++sy)for(int sx=left;sx<right;++sx) {
        const int u=std::clamp(int((float(sx)+0.5f-x)*16.0f/size),0,15);
        const int v=std::clamp(int((float(sy)+0.5f-y)*16.0f/size),0,15);
        const unsigned color=texture[1152+16*v+u];
        // PSMT8 CSM1 swaps index bits 3 and 4 in its 256-entry CLUT.
        const unsigned clut=128+4*((color&~24u)|((color&8u)<<1)|((color&16u)>>1));
        const int alpha=int(texture[clut+3]*opacity>>7);
        auto* dst=frame.rgba.data()+4*(640*sy+sx);
        for(unsigned c=0;c<3;++c){
            const int src=std::min(255,int(texture[clut+c]*light>>7));
            dst[c]=std::uint8_t(std::clamp(int(dst[c])+((src-int(dst[c]))*alpha>>7),0,255));
        }
    }
}
// 1836D8 -> 1769F0, sprite descriptor zero at 20C730. The source draws in
// submission order, with neutral RGBA (128s) and UV (0,0)..(1,1).
inline void draw_snow_particles(RasterFrame& frame,const GuestMemory& m,std::uint32_t task,
                                std::span<const std::uint8_t> texture) {
    check_particle_texture(frame,m,texture);
    const auto count=snow_particle_count(m,task),data=m.read_u32(task+44);
    auto f=[&](std::uint32_t p){return std::bit_cast<float>(m.read_u32(p));};
    for(std::uint32_t i=0;i<count;++i) {
        const auto p=data+20+32*i;
        const auto x=f(p),y=f(p+4),size=f(p+24);
        if(!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(size) || size<0 || size>32)
            throw std::runtime_error("1836D8 invalid original sprite geometry");
        if(!size || x+size<0 || x>f(0x23758c) || y<0 || y>f(0x237590))continue;
        draw_particle_sprite(frame,texture,x,y,size,128,128);
    }
}
}
