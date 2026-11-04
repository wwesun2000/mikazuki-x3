#pragma once
#include "../core/screen_ripple.hpp"
#include "field_sprite.hpp"
namespace kx3::platform {
inline void draw_screen_ripple_layer(RasterFrame& frame,const GuestMemory& memory,std::uint32_t task){
    const auto source=frame.rgba;
    const auto strips=draw_screen_ripple(memory,task);
    std::fill(frame.rgba.begin(),frame.rgba.end(),0);
    for(std::size_t i=3;i<frame.rgba.size();i+=4)frame.rgba[i]=255;
    for(unsigned field=0;field<2;++field)for(const auto& strip:strips)
        draw_field_sprite(frame,std::span(source).subspan(field*2560),5120,field,strip.xy,strip.uv);
}
}
