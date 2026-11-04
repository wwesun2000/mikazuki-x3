#pragma once
#include "../core/mystery_panel.hpp"
#include "../core/guest_memory.hpp"
#include "raster_frame.hpp"
#include <algorithm>
#include <bit>

namespace kx3::platform {
// The original 135CF8 emits paired UV/XYZ2 values in 12.4 coordinates.
// Keep sprite submission order, source RGBA modulation and GS field height.
inline RasterFrame render_mystery_panel(const GuestMemory& m){
    if(!mystery::active(m) || !m.read_u32(mystery::sprite_count))return {};
    RasterFrame frame{640,448,std::vector<std::uint8_t>(640*448*4)};
    auto half=[](unsigned word,unsigned shift){return int(std::uint16_t(word>>shift));};
    const unsigned count=m.read_u32(mystery::sprite_count);
    if(count>256)throw std::runtime_error("Invalid number of saved panel sprites");
    for(unsigned n=0;n<count;++n){
        const auto p=mystery::sprites+n*mystery::sprite_size,addr=m.read_u32(p);
        const auto w=m.read_u32(p+4),h=m.read_u32(p+8),xy=m.read_u32(p+12),end=m.read_u32(p+16);
        const auto uv=m.read_u32(p+20),uv1=m.read_u32(p+24),rgba=m.read_u32(p+28);
        if(!w || !h || w>1024 || h>1024 || addr<mystery::main_file ||
           std::uint64_t(addr)+4ull*w*h>mystery::slots+4*mystery::slot_capacity)throw std::runtime_error("Invalid saved panel texture");
        const auto tex=m.bytes(addr,std::size_t(w)*h*4);
        int left=(half(xy,0)-0x6c00)/16,top=(half(xy,16)-0x7900)/8;
        int right=(half(end,0)-0x6c00)/16,bottom=(half(end,16)-0x7900)/8;
        if(right<=left || bottom<=top)continue;
        const int u0=half(uv,0),v0=half(uv,16),du=half(uv1,0)-u0,dv=half(uv1,16)-v0;
        for(int y=std::max(0,top);y<std::min(448,bottom);++y){
            const auto v=std::clamp((v0+(y-top)*dv/(bottom-top))/16,0,int(h)-1);
            for(int x=std::max(0,left);x<std::min(640,right);++x){
                const auto u=std::clamp((u0+(x-left)*du/(right-left))/16,0,int(w)-1);
                const auto* from=tex.data()+4*(v*w+u);
                const unsigned alpha=std::min(255u,from[3]*(rgba>>24)/128*255/128);
                if(!alpha)continue;
                auto* to=frame.rgba.data()+4*(640*y+x);
                const unsigned old=to[3]*(255-alpha),sum=alpha*255+old;
                for(unsigned ch=0;ch<3;++ch){
                    const unsigned color=std::min(255u,from[ch]*((rgba>>(8*ch))&255u)/128);
                    to[ch]=std::uint8_t((color*alpha*255+to[ch]*old+sum/2)/sum);
                }
                to[3]=std::uint8_t((sum+127)/255);
            }
        }
    }
    return frame;
}
}
