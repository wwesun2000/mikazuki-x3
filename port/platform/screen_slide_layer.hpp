#pragma once
#include "../core/guest_memory.hpp"
#include "../core/screen_slide.hpp"
#include "field_sprite.hpp"
#include <algorithm>
#include <cmath>

namespace kx3::platform {
// 18B408 uploads the captured field to TBP 1680, copies this frame to 8000,
// clears, then draws two opaque translated sprites in that order (8000,1680).
inline void draw_screen_slide_layer(RasterFrame& frame,const GuestMemory& m,std::uint32_t task){
    if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4)
        throw std::runtime_error("18B408 requires a woven 640x448 surface");
    const auto commands=draw_screen_slide(m,task);
    const bool outgoing=m.read_u32(task+24)==0x18a9f0;
    const bool saved_first=m.read_u32(task+24)==0x18aef8;
    const auto current=frame.rgba;
    if(!outgoing){
        std::fill(frame.rgba.begin(),frame.rgba.end(),0);
        for(unsigned i=3;i<frame.rgba.size();i+=4)frame.rgba[i]=255;
    }
    for(int field=0;field<2;++field){
        const auto plane=m.read_u32(0x236114+4*field);
        if(!plane)throw std::runtime_error("18B408 requires the saved display field");
        const auto old=m.bytes(plane,640*224*4);
        for(unsigned which=0;which<(outgoing?1u:commands.size());++which){
            const bool saved=outgoing || (saved_first?which==0:which==1);
            const auto pixels=saved?old:std::span<const std::uint8_t>(current).subspan(field*2560);
            draw_field_sprite(frame,pixels,saved?2560:5120,field,commands[which],{0,0,639,223});
        }
    }
}
}
