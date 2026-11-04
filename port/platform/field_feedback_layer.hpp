#pragma once
#include "../core/field_feedback.hpp"
#include "field_sprite.hpp"
namespace kx3::platform {
// Original FRAME and TEX0 address the same field. PCSX2 2.8.2 software
// readback matches a fresh source image before each of the ordered sprites.
inline void draw_field_feedback_layer(RasterFrame& frame,const GuestMemory& memory,std::uint32_t task){
    if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4)
        throw std::runtime_error("Invalid original feedback framebuffer");
    std::vector<std::uint8_t> source(640*224*4);
    for(unsigned field=0;field<2;++field){
        const auto draw=draw_field_feedback(memory,task,field);
        for(const auto& sprite:draw){
            if(!sprite.alpha)continue;
            for(unsigned row=0;row<224;++row)
                std::copy_n(frame.rgba.data()+(2*row+field)*2560,2560,source.data()+row*2560);
            draw_field_sprite(frame,source,2560,field,sprite.coordinates.xy,sprite.coordinates.uv,sprite.alpha);
        }
    }
}
}
