#pragma once
#include "../core/expandband_recomp.hpp"
#include "raster_frame.hpp"
#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace kx3::platform {
// 1847A8 -> 177FA8 (line), 176AC8 (TEXFLUSH), 178910 (framebuffer sprite).
inline void draw_expandband_layer(RasterFrame& frame,const GuestMemory& memory,std::uint32_t task) {
    if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4)
        throw std::runtime_error("1847A8 requires two 640x224 fields");
    const std::array commands={draw_expandband(memory,task,0),draw_expandband(memory,task,1)};
    for(unsigned field=0;field<2;++field) {
        const auto& cmd=commands[field];
        if(cmd.texture_base!=(field?0x8c0u:0u) || cmd.flags!=0 ||
           cmd.rgba!=std::array<unsigned,4>{128,128,128,128} ||
           cmd.xy[0]!=0 || cmd.xy[2]!=639 || cmd.uv[0]!=0 || cmd.uv[2]!=639 ||
           cmd.uv[1]!=cmd.xy[1] || cmd.uv[3]!=223)
            throw std::runtime_error("Unsupported 178910 expandband sprite");
        if(!cmd.black_strip)continue;
        if(cmd.black_xy!=std::array<float,4>{0,0,639,0} || cmd.black_rgba!=std::array<unsigned,4>{0,0,0,128})
            throw std::runtime_error("Unsupported 177FA8 expandband line");
        // PRIM=LINE. A horizontal segment excludes its final endpoint.
        for(unsigned x=0;x<639;++x){
            auto* p=frame.rgba.data()+(field*640+x)*4;
            p[0]=p[1]=p[2]=0;p[3]=255;
        }
    }
    const auto texture=frame.rgba; // TEXFLUSH after the optional line, before feedback sampling.
    for(unsigned field=0;field<2;++field){
        const auto& cmd=commands[field];
        // 177138 case 4, VFT(O)I4. GS tests coverage at integer pixel centers.
        const auto packed=[](float value,unsigned mask){
            if(!std::isfinite(value))throw std::runtime_error("Non-finite 1847A8 geometry");
            const double scaled=std::clamp(double(value)*16.,-2147483648.,2147483647.);
            return int(std::uint32_t(std::int32_t(scaled))&mask);
        };
        // The original two FRAME_1 environments carry XYOFFSET_1.OFY=7900/7908.
        const int origin=1936*16+8*int(field);
        int y0=packed(1936.f+cmd.xy[1],0xffff)-origin,y1=packed(1936.f+(cmd.xy[3]+1.f),0xffff)-origin;
        int v0=packed(cmd.uv[1],0x3fff),v1=packed(cmd.uv[3]+1.5f,0x3fff);
        if(y1<y0){std::swap(y0,y1);std::swap(v0,v1);}
        if(y1==y0)continue;
        const int first=std::max(0,(y0+15)/16),end=std::min(224,(y1+15)/16);
        for(int y=first;y<end;++y){
            const auto numerator=std::int64_t(v0)*(y1-y0)+std::int64_t(v1-v0)*(16*y-y0);
            const auto v=std::clamp(int(numerator/(16*(y1-y0))),0,223);
            // U runs from 0 to 640.5 over 640 pixels. NEAREST selects x at every x.
            const auto* in=texture.data()+(2*v+field)*2560;
            auto* out=frame.rgba.data()+(2*y+field)*2560;
            std::copy_n(in,2560,out);
        }
    }
}
}
