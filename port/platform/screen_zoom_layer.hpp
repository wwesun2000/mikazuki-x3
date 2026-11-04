#pragma once
#include "../core/screen_zoom.hpp"
#include "field_sprite.hpp"
namespace kx3::platform {
inline void draw_screen_zoom_layer(RasterFrame& frame,const ZoomDraw& draw){
    const auto source=frame.rgba;
    std::fill(frame.rgba.begin(),frame.rgba.end(),0);
    for(unsigned i=3;i<frame.rgba.size();i+=4)frame.rgba[i]=255;
    for(unsigned field=0;field<2;++field)
        draw_field_sprite(frame,std::span(source).subspan(field*2560),5120,field,draw.xy,draw.uv);
}
}
