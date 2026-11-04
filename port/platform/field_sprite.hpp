#pragma once
#include "raster_frame.hpp"
#include "../core/ee_scalar.hpp"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <span>
#include <stdexcept>

namespace kx3::platform {
// Original 178910 -> 177F48 nearest/clamped sprite, one woven output field.
// The caller retains its source image before overwriting any destination.
inline void draw_field_sprite(RasterFrame& frame,std::span<const std::uint8_t> source,
                              unsigned pitch,unsigned field,const std::array<float,4>& xy,
                              const std::array<float,4>& uv,unsigned alpha=128,bool texture_alpha=false){
    if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4 ||
       field>1 || alpha>128 || source.size()<std::size_t(pitch)*223+2560)
        throw std::runtime_error("Invalid original field sprite surface");
    auto fixed=[](float value,int origin,unsigned mask){
        const float scaled=ee::ee_add_sub(value,float(origin),false)*16;
        if(!std::isfinite(scaled) || std::abs(scaled)>2147483000.0f)
            throw std::runtime_error("Invalid original GS sprite coordinate");
        return int(std::uint32_t(int(scaled))&mask)-origin*16;
    };
    const int x0=fixed(xy[0],1728,0xffff),x1=fixed(ee::ee_add_sub(xy[2],1,false),1728,0xffff);
    const int y0=fixed(xy[1],1936,0xffff)-int(8*field),y1=fixed(ee::ee_add_sub(xy[3],1,false),1936,0xffff)-int(8*field);
    if(x0==x1 || y0==y1)return;
    if(x0>x1 || y0>y1)throw std::runtime_error("Unverified reversed original GS sprite");
    const int u0=fixed(uv[0],0,0x3fff),u1=fixed(ee::ee_add_sub(uv[2],1.5f,false),0,0x3fff);
    const int v0=fixed(uv[1],0,0x3fff),v1=fixed(ee::ee_add_sub(uv[3],1.5f,false),0,0x3fff);
    const int left=std::clamp((x0+15)/16,0,640),right=std::clamp((x1+15)/16,0,640);
    const int top=std::clamp((y0+15)/16,0,224),bottom=std::clamp((y1+15)/16,0,224);
    std::array<unsigned,640> xs{};
    for(int x=left;x<right;++x)
        xs[x]=unsigned(std::clamp<std::int64_t>((std::int64_t(u0)*(x1-x0)+std::int64_t(u1-u0)*(16*x-x0))/
                                               (std::int64_t(x1-x0)*16),0,639));
    for(int y=top;y<bottom;++y){
        const auto v=std::clamp<std::int64_t>((std::int64_t(v0)*(y1-y0)+std::int64_t(v1-v0)*(16*y-y0))/
                                            (std::int64_t(y1-y0)*16),0,223);
        const auto* row=source.data()+v*pitch;
        auto* target=frame.rgba.data()+(2*y+field)*2560;
        for(int x=left;x<right;++x){
            const auto* sample=row+4*xs[x];auto* pixel=target+4*x;
            // Host text surfaces use alpha 0..255. TCC=1 modulates the source
            // alpha by vertex alpha; the existing framebuffer paths ignore it.
            const unsigned weight=texture_alpha?(alpha*unsigned(sample[3])+127)/255:alpha;
            if(!weight)continue;
            if(weight==128 && !texture_alpha)std::copy_n(sample,4,pixel);
            else for(unsigned channel=0;channel<3;++channel)
                pixel[channel]=std::uint8_t(int(pixel[channel])+((int(sample[channel])-int(pixel[channel]))*int(weight)>>7));
        }
    }
}
}
