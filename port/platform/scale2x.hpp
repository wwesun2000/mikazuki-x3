#pragma once
#include <algorithm>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

namespace kx3::platform {
// Four-neighbour Scale2x. At an image edge, reuse the nearest source pixel.
inline std::vector<std::uint32_t> scale2x_pixels(std::span<const std::uint32_t> input,
                                                unsigned width,unsigned height){
    if(!width || !height || width>std::numeric_limits<unsigned>::max()/2 ||
       width>std::numeric_limits<std::size_t>::max()/height/4 || input.size()!=std::size_t(width)*height)
        throw std::invalid_argument("Invalid Scale2x source dimensions");
    std::vector<std::uint32_t> output(input.size()*4);
    const auto stride=std::size_t(width)*2;
    for(unsigned y=0;y<height;++y){
        const auto* row=input.data()+std::size_t(y)*width;
        const auto* above=y?row-width:row;const auto* below=y+1<height?row+width:row;
        auto* top=output.data()+std::size_t(y)*2*stride;auto* bottom=top+stride;
        for(unsigned x=0;x<width;++x){
            const auto center=row[x],up=above[x],down=below[x];
            const auto left=row[x?x-1:0],right=row[std::min(width-1,x+1)];
            const bool edge=up!=down && left!=right;
            top[2*x]=edge && up==left?left:center;
            top[2*x+1]=edge && up==right?right:center;
            bottom[2*x]=edge && down==left?left:center;
            bottom[2*x+1]=edge && down==right?right:center;
        }
    }
    return output;
}
}
