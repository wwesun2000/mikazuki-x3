#pragma once
#include "../core/expandblur.hpp"
#include "raster_frame.hpp"
#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace kx3::platform {
// 183088 captures each field once, clears the target and submits 21 sprites
// through 178910. The first is opaque; each history sample uses GS ALPHA=44.
inline void draw_expandblur_layer(RasterFrame& frame,const BlurDraw& draws){
    if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4 || draws.front().alpha!=128)
        throw std::runtime_error("Unexpected 183088 GS surface or first sprite");
    const auto texture=frame.rgba;
    bool all_first=true;
    auto fixed=[](float v){
        if(!std::isfinite(v) || std::abs(v)>1000000)throw std::runtime_error("Invalid 183088 texture coordinate");
        return int(std::uint32_t(int(v*16))&0x3fff);
    };
    for(const auto& sprite:draws){
        if(&sprite!=&draws.front() && all_first && sprite.uv==draws.front().uv)continue;
        all_first=all_first && sprite.uv==draws.front().uv;
        const auto& uv=sprite.uv;
        const int u0=fixed(uv[0]),u1=fixed(uv[2]+1.5f),v0=fixed(uv[1]),v1=fixed(uv[3]+1.5f);
        std::array<unsigned,640> xs;
        for(int x=0;x<640;++x)xs[x]=std::clamp((u0*640+(u1-u0)*x)/(640*16),0,639);
        for(int y=0;y<448;++y){
            const int v=std::clamp((v0*448+(v1-v0)*y)/(448*16),0,223);
            const auto* row=texture.data()+(2*v+(y&1))*2560;
            auto* dst=frame.rgba.data()+y*2560;
            for(const auto x:xs){
                const auto* src=row+x*4;
                for(int c=0;c<3;++c)dst[c]+=((int(src[c])-dst[c])*int(sprite.alpha))>>7;
                dst+=4;
            }
        }
    }
}
}
