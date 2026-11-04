#pragma once
#include "../core/circlemask.hpp"
#include "../core/guest_memory.hpp"
#include "raster_frame.hpp"
#include <algorithm>
#include <cmath>

namespace kx3::platform {
// 1769F0 -> 177F28 uses ST with Q=1 and TEX1=0. This sprite does
// not receive the +1/+1.5 end adjustments of the FST framebuffer sprites.
inline int circle_vertex(float v,int origin){
    if(!std::isfinite(v) || std::abs(v)>32767)throw std::runtime_error("Circle vertex outside GS range");
    return int(std::uint32_t(int((float(origin)+v)*16))&65535)-16*origin;
}
template<std::size_t N>
inline std::array<int,N> circle_samples(int first,int last){
    std::array<int,N> out;out.fill(-1);
    if(first==last)return out;
    const int lo=std::clamp((std::min(first,last)+15)/16,0,int(N));
    const int hi=std::clamp((std::max(first,last)+15)/16,0,int(N));
    for(int i=lo;i<hi;++i)
        out[i]=std::clamp((16*i-first)*128/(last-first),0,127);
    return out;
}
inline void draw_circlemask_layer(RasterFrame& frame,const GuestMemory& m,std::span<const std::uint8_t> texture,
                                  const CircleDraw& draw){
    if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4 || texture.size()!=8384 ||
       !std::equal(texture.begin(),texture.begin()+128,m.bytes(0x23a480,128).begin()))
        throw std::runtime_error("193CB8 unbound field or mask texture");
    const auto &saved=draw.at(0),&mask=draw.at(1);
    const bool opening=mask.test==2;
    const bool graduated=draw.size()==46;
    if((draw.size()!=4 && !graduated) || (graduated && !opening) || saved.source!=CircleSource::saved ||
       saved.test!=6 || saved.depth!=(opening?1u:100u) || saved.alpha!=128)
        throw std::runtime_error("Unsupported circle mask GS pass sequence");
    // Mode 10 repeats the same geometry with fifteen successive CLUTs.
    // Accumulate the current-field contribution once per texture index.
    // Index 16 lies outside the sprite. Alpha-zero clears reset depth only.
    std::array<unsigned,17> weight{};
    for(unsigned j=0;j<(graduated?15u:1u);++j){
        const auto& layer=draw[1+3*j];const auto& current=draw[2+3*j];const auto& clear=draw[3+3*j];
        if(layer.source!=CircleSource::mask || layer.test!=(opening?2u:3u) ||
           layer.depth!=(opening?100u:1u) || layer.xy!=mask.xy ||
           layer.palette!=(opening?0x20d9f0u:0x20e170u)+128*j || current.source!=CircleSource::current ||
           current.test!=4 || current.depth!=10 || current.alpha!=128-8*j || clear.source!=CircleSource::solid ||
           clear.test!=6 || clear.depth!=0 || clear.alpha)
            throw std::runtime_error("Unsupported circle mask depth or blend state");
        const auto palette=m.bytes(layer.palette,128);
        for(unsigned i=0;i<weight.size();++i){
            const bool writes_depth=i<16 && !palette[4*((i&7)+2*(i&8))+3];
            if(writes_depth!=opening)weight[i]+=((128-weight[i])*current.alpha+64)/128;
        }
    }
    const auto xs=circle_samples<640>(circle_vertex(mask.xy[0],1728),circle_vertex(mask.xy[2],1728));
    for(int field=0;field<2;++field){
        const auto addr=m.read_u32(0x236114+4*field);
        if(!addr)throw std::runtime_error("193CB8 requires captured fields");
        const auto old=m.bytes(addr,640*224*4);
        const auto ys=circle_samples<224>(circle_vertex(mask.xy[1],1936)-8*field,circle_vertex(mask.xy[3],1936)-8*field);
        for(int y=0;y<224;++y){
            const auto* src=old.data()+2560*y;
            auto* dst=frame.rgba.data()+2560*(2*y+field);
            for(int x=0;x<640;++x){
                unsigned index=16;
                if(xs[x]>=0 && ys[y]>=0){
                    const auto packed=texture[192+ys[y]*64+xs[x]/2];
                    index=(packed>>(4*(xs[x]&1)))&15;
                }
                const unsigned alpha=weight[index];
                if(!alpha)std::copy_n(src+4*x,4,dst+4*x);
                else if(alpha<128)for(unsigned ch=0;ch<4;++ch){
                    const auto i=4*x+ch;
                    dst[i]=std::uint8_t((src[i]*(128-alpha)+dst[i]*alpha+64)/128);
                }
            }
        }
    }
}
}
