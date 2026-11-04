#pragma once
#include "../core/actor_choice.hpp"
#include "raster_frame.hpp"
#include <algorithm>
#include <span>
#include <stdexcept>

namespace kx3::platform {
// Source 14B2A0 uses field coordinates. Its 112x256 portrait slices become
// 112x256 pixels on the host's 640x448 logical surface.
inline RasterFrame render_actor_panel(const ActorChoiceView& panel,std::span<const std::uint8_t> pixels){
    if(!panel.open)return {};
    if(pixels.size()!=2926592 || panel.opacity>128)throw std::runtime_error("Invalid 14B2A0 actor panel data");
    RasterFrame out{640,448,std::vector<std::uint8_t>(640*448*4)};
    auto sprite=[&](unsigned offset,unsigned x,unsigned y,unsigned w,unsigned h,unsigned opacity,unsigned gain){
        if(offset>pixels.size() || std::size_t(w)*h*4>pixels.size()-offset || x+w>640 || y+h>448)
            throw std::runtime_error("Actor panel descriptor exceeds the original atlas");
        for(unsigned r=0;r<h;++r)for(unsigned c=0;c<w;++c){
            const auto* from=pixels.data()+offset+4*(r*w+c);
            const auto alpha=std::min(255u,(from[3]*opacity/128)*255/128);
            if(!alpha)continue;
            auto* to=out.rgba.data()+4*((y+r)*640+x+c);
            const auto old=to[3]*(255-alpha),weight=alpha*255+old;
            for(unsigned ch=0;ch<3;++ch)to[ch]=std::uint8_t(((from[ch]*gain/128)*alpha*255+to[ch]*old+weight/2)/weight);
            to[3]=std::uint8_t((weight+127)/255);
        }
    };
    sprite(0,0,32,640,40,panel.opacity,127);
    sprite(0x19000,0,388,640,28,panel.opacity,127);
    for(unsigned i=0;i<4;++i){
        if(panel.portrait[i]>=12 || panel.highlight[i]>127)throw std::runtime_error("Invalid 14B6E0 source character card");
        const unsigned at=0x2a800+panel.portrait[i]*0x38000,x=88+112*i;
        sprite(at+112*256*4,x,88,112,256,panel.opacity,127);
        sprite(at,x,88,112,256,panel.opacity*panel.highlight[i]/127,127);
    }
    return out;
}
}
