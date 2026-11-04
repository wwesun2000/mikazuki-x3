#pragma once
#include "../core/guest_memory.hpp"
#include "raster_frame.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdint>

namespace kx3::platform {
// 192258 draws the saved 640x224 field first, then up to eight triangles
// textured with the current field. Coordinates and texture samples use GS 12.4.
inline void draw_screen_transition(RasterFrame& frame,const GuestMemory& m,std::uint32_t task) {
    if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4)
        throw std::runtime_error("192258 requires a 640x448 game surface");
    const auto current=frame.rgba;
    for(unsigned field=0;field<2;++field){
        const auto plane=m.read_u32(0x236114+4*field);
        if(!plane)throw std::runtime_error("192258 missing original display field");
        const auto saved=m.bytes(plane,640*224*4);
        for(unsigned row=0;row<224;++row)
            std::copy_n(saved.begin()+row*2560,2560,frame.rgba.begin()+(2*row+field)*2560);
    }
    struct Vertex {int x,y,u,v;};
    auto edge=[](const Vertex& a,const Vertex& b,int x,int y)->std::int64_t {
        return std::int64_t(b.x-a.x)*(y-a.y)-std::int64_t(b.y-a.y)*(x-a.x);
    };
    auto inclusive=[](const Vertex& a,const Vertex& b){return b.y<a.y || (b.y==a.y && b.x>a.x);};
    const auto data=m.read_u32(task+44);
    for(unsigned i=0;i<8;++i){
        const auto row=data+i*28;
        if(!m.read_u32(row+32))continue;
        std::array<Vertex,3> p;
        for(unsigned j=0;j<3;++j){
            const float x=std::bit_cast<float>(m.read_u32(row+8+4*j)),y=std::bit_cast<float>(m.read_u32(row+20+4*j));
            if(!std::isfinite(x)||!std::isfinite(y)||std::abs(x)>4096||std::abs(y)>4096)
                throw std::runtime_error("192258 invalid original triangle");
            // 177138 case 2 adjusts U of vertices 1/2 and V of vertex 2
            // before VFT(O)I4. The GS origin is (1728,1936) in this display mode.
            p[j]={int((x+1728.f)*16)-1728*16,int((y+1936.f)*16)-1936*16,
                  int((x+(j?0.5f:0.f))*16),int((y+(j==2?0.5f:0.f))*16)};
        }
        auto area=edge(p[0],p[1],p[2].x,p[2].y);
        if(!area)continue;
        if(area<0){std::swap(p[1],p[2]);area=-area;}
        const int left=std::max(0, std::min({p[0].x,p[1].x,p[2].x})/16);
        const int right=std::min(639,std::max({p[0].x,p[1].x,p[2].x})/16);
        const int top=std::max(0, std::min({p[0].y,p[1].y,p[2].y})/16);
        const int bottom=std::min(223,std::max({p[0].y,p[1].y,p[2].y})/16);
        const std::array<bool,3> closed{inclusive(p[1],p[2]),inclusive(p[2],p[0]),inclusive(p[0],p[1])};
        for(int y=top;y<=bottom;++y)for(int x=left;x<=right;++x){
            const auto a=edge(p[1],p[2],16*x,16*y),b=edge(p[2],p[0],16*x,16*y),c=area-a-b;
            if(a<int(!closed[0]) || b<int(!closed[1]) || c<int(!closed[2]))continue;
            const int u=std::clamp(int((a*p[0].u+b*p[1].u+c*p[2].u)/(16*area)),0,639);
            const int v=std::clamp(int((a*p[0].v+b*p[1].v+c*p[2].v)/(16*area)),0,223);
            for(int field=0;field<2;++field)
                std::copy_n(current.begin()+((2*v+field)*640+u)*4,4,frame.rgba.begin()+((2*y+field)*640+x)*4);
        }
    }
}
}
