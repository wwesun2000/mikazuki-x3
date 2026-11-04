#pragma once
#include "../core/screen_shake.hpp"
#include "field_sprite.hpp"
namespace kx3::platform {
inline void draw_screen_shake_layer(RasterFrame& frame,const ShakeDraw& draw){
    if(!draw.visible)return;
    const auto source=frame.rgba;
    for(unsigned sprite=0;sprite<2;++sprite)for(unsigned field=0;field<2;++field)
        draw_field_sprite(frame,std::span(source).subspan(field*2560),5120,field,
                          draw.sprites[sprite].xy,draw.sprites[sprite].uv,sprite?80:128);
}
}
