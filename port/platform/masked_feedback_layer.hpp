#pragma once
#include "../core/masked_feedback.hpp"
#include "circlemask_layer.hpp"
#include "field_sprite.hpp"

namespace kx3::platform {
inline void draw_masked_feedback_layer(RasterFrame& frame,const GuestMemory& memory,
                                      std::span<const std::uint8_t> texture,std::uint32_t task){
    if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4 || texture.size()!=8384 ||
       !std::equal(texture.begin(),texture.begin()+128,memory.bytes(0x23a480,128).begin()))
        throw std::runtime_error("17F230 mask descriptor differs from original");
    std::vector<std::uint8_t> source(640*224*4);
    for(unsigned field=0;field<2;++field){
        const auto draw=draw_masked_feedback(memory,task,field);
        // The two retail cues use radius 1. The CTF and the persistent
        // 193CB8 restore palette agree on their sampled alpha-zero texels.
        // Evidence: feedback-mask-26/CLUT-LIFECYCLE.md.
        if(draw.mask!=std::array<float,4>{319,223,2,2})
            throw std::runtime_error("Unverified inherited palette for focus-mask dimensions");
        const auto xs=circle_samples<640>(circle_vertex(draw.mask[0],1728),circle_vertex(draw.mask[0]+draw.mask[2],1728));
        const auto ys=circle_samples<224>(circle_vertex(draw.mask[1]*.5f,1936)-int(8*field),
                                         circle_vertex((draw.mask[1]+draw.mask[3])*.5f,1936)-int(8*field));
        struct BlockedPixel {std::size_t offset;std::array<std::uint8_t,4> rgba;};
        std::vector<BlockedPixel> blocked;
        for(unsigned y=0;y<224;++y)if(ys[y]>=0)for(unsigned x=0;x<640;++x)if(xs[x]>=0){
            const auto texel=texture[192+64*ys[y]+xs[x]/2];
            const auto index=(texel>>(4*(xs[x]%2)))&15;
            if(texture[128+4*index+3])continue;
            BlockedPixel pixel{4*((2*y+field)*640+x),{}};
            std::copy_n(frame.rgba.begin()+pixel.offset,4,pixel.rgba.begin());blocked.push_back(pixel);
        }
        for(const auto& sprite:draw.sprites){
            if(!sprite.alpha)continue;
            for(unsigned row=0;row<224;++row)
                std::copy_n(frame.rgba.data()+(2*row+field)*2560,2560,source.data()+row*2560);
            draw_field_sprite(frame,source,2560,field,sprite.coordinates.xy,sprite.coordinates.uv,sprite.alpha);
            // Alpha-zero mask writes Z100. The following Z1 sprites preserve
            // these pixels while sampling the updated field for every draw.
            for(const auto& pixel:blocked)std::copy(pixel.rgba.begin(),pixel.rgba.end(),frame.rgba.begin()+pixel.offset);
        }
    }
}
}
