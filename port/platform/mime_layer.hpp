#pragma once
#include "../core/mime_effect.hpp"
#include "raster_frame.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>

namespace kx3::platform {
// 17C698 copies the current field to GS VRAM, then emits 9x9 strips via
// 1787F0 -> 177A50. The original vertex order submitted is TL,TR,BL,BR.
inline void draw_mime_layer(RasterFrame& frame,const GuestMemory& m,std::uint32_t task){
    const auto grid=mime_grid(m,task),data=m.read_u32(task+44);
    if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4)
        throw std::runtime_error("17C698 needs the original full display");
    const auto source=frame.rgba;
    auto f=[&](std::uint32_t p){return std::bit_cast<float>(m.read_u32(p));};
    std::array<int,3> rgb;
    for(unsigned c=0;c<3;++c){
        const float v=f(data+16+4*c);
        if(!std::isfinite(v) || v<0 || v>255)throw std::runtime_error("17C698 invalid source modulation");
        rgb[c]=int(v);
    }
    struct Point{double x,y,u,v;};
    auto point=[&](unsigned index,bool right){
        const auto p=grid+index*36;const float x=f(p+8),y=f(p+12);
        if(!std::isfinite(x) || !std::isfinite(y) || std::abs(x)>4096 || std::abs(y)>4096)
            throw std::runtime_error("17C698 invalid source vertex coordinates");
        return Point{std::trunc(x*16)/16.0,std::trunc(y*16)/16.0,
            double(f(p+28)+(right?f(0x237318):0.f))*1024,double(f(p+32)+(right?f(0x23731c):0.f))*256};
    };
    auto triangle=[&](Point a,Point b,Point c){
        const auto cross=[](double x,double y,double u,double v){return x*v-y*u;};
        const double area=cross(b.x-a.x,b.y-a.y,c.x-a.x,c.y-a.y);
        if(!area)return;
        const int minx=std::max(0,int(std::floor(std::min({a.x,b.x,c.x}))));
        const int maxx=std::min(640,int(std::ceil(std::max({a.x,b.x,c.x}))));
        const int miny=std::max(0,int(std::floor(std::min({a.y,b.y,c.y}))));
        const int maxy=std::min(224,int(std::ceil(std::max({a.y,b.y,c.y}))));
        for(int y=miny;y<maxy;++y)for(int x=minx;x<maxx;++x){
            const double px=x+0.5-a.x,py=y+0.5-a.y;
            const auto wb=cross(px,py,c.x-a.x,c.y-a.y)/area,wc=cross(b.x-a.x,b.y-a.y,px,py)/area,wa=1-wb-wc;
            if(wa<0 || wb<0 || wc<0)continue;
            // 177038(flags=0) selects nearest sampling. Both display fields
            // use the same submitted geometry and retain their own source lines.
            const int sx=std::clamp(int(std::floor(wa*a.u+wb*b.u+wc*c.u)),0,639);
            const int sy=std::clamp(int(std::floor(wa*a.v+wb*b.v+wc*c.v)),0,223);
            for(int field=0;field<2;++field){
                auto* dst=frame.rgba.data()+4*((2*y+field)*640+x);
                const auto* src=source.data()+4*((2*sy+field)*640+sx);
                for(int i=0;i<3;++i)dst[i]=std::uint8_t(std::min(255,(src[i]*rgb[i])>>7));
            }
        }
    };
    for(unsigned y=0;y<9;++y)for(unsigned x=0;x<9;++x){
        auto i=10*y+x;
        const auto tl=point(i,false),tr=point(i+1,true),bl=point(i+10,false),br=point(i+11,true);
        triangle(tl,tr,bl);triangle(tr,br,bl);
    }
}
}
