#pragma once
#include "../core/sab_animation.hpp"
#include "raster_frame.hpp"
#include "gs_blend.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>

namespace kx3::platform {
// 146F78 / 146D20. Two observed original GIF chains are retained in
// oracle-sab-gif-v1. Reconstruct the 128-line scratch strips as RGBA.
inline void draw_sab_layer(RasterFrame& frame,const GuestMemory& m,const SabDisplay& display){
    using u32=std::uint32_t;
    if(display.bytes.empty())return;
    if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4)
        throw std::runtime_error("146F78 needs original 640x448 SAB composition");
    if(m.read_u32(0x236478) || m.read_u32(0x23647c) || m.read_u32(0x236468)!=UINT32_MAX)
        throw std::runtime_error("146F78 unsupported debug blend/strip exclusion");
    const auto b=display.bytes;
    const auto info=inspect_sab_file(b);
    const auto l=inspect_sab_layer(b,info,display.frame);
    const auto strength=std::bit_cast<float>(m.read_u32(0x236460))*std::bit_cast<float>(m.read_u32(0x236480));
    if(!std::isfinite(strength) || strength<0 || strength>255)throw std::runtime_error("146F78 invalid source alpha");
    const int vertex_alpha=int(strength),edge=int(m.read_u32(0x23646c));
    if(edge!=1)throw std::runtime_error("146D20 unsupported texture clamp");
    struct Sample {int first,second,fraction;};
    // GS uses 12.4 texture coordinates and a half-texel bilinear footprint.
    auto sample=[](int offset,int pixels,int start,int end,int bias,int low,int high){
        const int uv16=start*16+bias+((2*offset+1)*(end-start)*8)/pixels-8;
        const int a=uv16>>4;
        return Sample{std::clamp(a,low,high),std::clamp(a+1,low,high),uv16&15};
    };
    auto filter=[](Sample x,Sample y,auto&& texel){
        auto row=[&](int v){return ((16-x.fraction)*texel(x.first,v)+x.fraction*texel(x.second,v))>>4;};
        return ((16-y.fraction)*row(y.first)+y.fraction*row(y.second))>>4;
    };
    const auto width=std::min(l.width,640-l.x),height=std::min(l.height,448-l.y);
    for(u32 y=0;y<height;++y){
        const int strip=int(y/128)*128,dy=int(y)-strip,rows=std::min(128,int(height)-strip);
        const int begin=strip>>info.colorshift,last=begin+(rows>>info.colorshift)-1;
        if(last<begin)throw std::runtime_error("146F78 truncated color strip");
        const auto cy=sample(dy,rows,begin,last,0,begin,std::max(begin,last-edge));
        const auto my=sample(dy,rows,0,rows,8,0,rows-edge);
        for(u32 x=0;x<width;++x){
            const auto cx=sample(x,l.width,0,l.color_width-1,0,0,std::max(0,int(l.color_width)-1-edge));
            const auto mx=sample(x,l.width,0,l.mask_width-1,8,0,std::max(0,int(l.mask_width)-1-edge));
            const int mask=filter(mx,my,[&](int u,int v){
                const auto i=(strip+v)*l.mask_width+u;
                const auto index=(b[l.mask+i/2]>>(4*(i&1)))&15;
                return int(b[l.mask_palette+4*index+3]);
            });
            const int opacity=mask*vertex_alpha>>7;
            if(!opacity)continue;
            auto* dst=frame.rgba.data()+4*((l.y+y)*640+l.x+x);
            for(int c=0;c<3;++c){
                const int color=filter(cx,cy,[&](int u,int v){
                    const auto i=b[l.colors+v*l.color_width+u];
                    const auto clut=(i&~24)|((i&8)<<1)|((i&16)>>1);
                    return int(b[info.color_palette+4*clut+c]);
                });
                // 147448 sets RGBAQ.A to 0x68. The final pass uses the source vertex alpha.
                const int scratch=source_over_channel(color,dst[c],104);
                dst[c]=std::uint8_t(std::clamp(source_over_channel(scratch,dst[c],opacity),0,255));
            }
        }
    }
}
}
