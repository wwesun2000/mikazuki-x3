#pragma once
#include "../core/gradefilter.hpp"
#include "raster_frame.hpp"
#include <algorithm>
#include <stdexcept>

namespace kx3::platform {
// 181660 copies the current 640x224 page to GS texture base 8000, then
// submits a Gouraud-shaded triangle strip with identical left/right colors.
inline void draw_gradefilter_layer(RasterFrame& frame,const GradeColors& colors){
    if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4 ||
       colors.top[3]!=128 || colors.bottom[3]!=128)
        throw std::runtime_error("Unsupported 181660 GS surface or alpha");
    for(int y=0;y<448;++y){
        std::array<int,3> light{};
        // Field 1 has a half-row XYOFFSET. On the woven surface this
        // corresponds to the odd y samples between the even field's rows.
        for(unsigned c=0;c<3;++c){
            const int top=colors.top[c]&255,bottom=colors.bottom[c]&255;
            light[c]=((448-y)*top+y*bottom)*128/448;
        }
        auto* p=frame.rgba.data()+y*2560;
        for(unsigned x=0;x<640;++x,p+=4)for(unsigned c=0;c<3;++c)
            p[c]=std::uint8_t(std::min(255,p[c]*light[c]>>14));
    }
}
}
