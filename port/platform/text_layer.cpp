#include "text_layer.hpp"
#include "../core/guest_memory.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <stdexcept>

namespace kx3::platform {
namespace {
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using Byte = std::uint8_t;
constexpr u32 screen_width=640, screen_height=448;

struct Atlas {
    u32 width,height;
    std::span<const Byte> pixels, palette;
};

u64 little64(std::span<const Byte> bytes) {
    u64 result=0;
    for (unsigned i=0;i<8;++i) result |= u64(bytes[i])<<(8*i);
    return result;
}

Atlas resolve_atlas(const GuestMemory& m, u32 channel, u64 tex0,
                    std::span<const TextAtlasResource> resources) {
    const u32 w=m.read_u32(channel+16), h=m.read_u32(channel+20);
    const u32 tw=1u<<((tex0>>26)&15), th=1u<<((tex0>>30)&15);
    if (((tex0>>20)&63)!=20 || ((tex0>>34)&1)!=1 || ((tex0>>35)&3)!=0)
        throw std::runtime_error("Unsupported text sprite texture format or modulation");
    if ((tex0&0x3fff)==(m.read_u32(channel+32)&0x3fff) && ((tex0>>37)&0x3fff)==0x2e40
        && tw==w && th==h && w<=1024 && h<=1024) {
        return {w,h,m.bytes(m.read_u32(channel+28),std::size_t(w)*h/2),m.bytes(0x1e44180,64)};
    }
    for (const auto& resource: resources) {
        if (resource.index!=0 && resource.index!=4) continue;
        const auto raw=resource.encoded;
        if (raw.size()!=8384 || tw!=128 || th!=128 || little64(raw.subspan(0x70,8))!=tex0) continue;
        // Check the descriptor the original program actually installed.
        const auto header=m.bytes(0x23a300+128*resource.index,128);
        if (!std::equal(header.begin(),header.end(),raw.begin()))
            throw std::runtime_error("Text resource differs from the installed original descriptor");
        return {128,128,raw.subspan(192),raw.subspan(128,64)};
    }
    throw std::runtime_error("Missing original text atlas for sprite TEX0");
}

int uv_pixel(const GuestMemory& m, u32 address, u32 dimension) {
    const float uv=std::bit_cast<float>(m.read_u32(address));
    if (!std::isfinite(uv) || uv<0 || uv>1) throw std::runtime_error("Invalid text sprite UV");
    return int(std::lround(uv*float(dimension)));
}

// A portable straight-alpha layer. GS color/alpha modulation uses unity 128.
// Keeping the layer separate allows composition over any host scene texture.
void composite(Byte* dst, const Byte* texel, const std::array<Byte,3>& color, unsigned opacity) {
    const unsigned alpha=std::min(255u,(unsigned(texel[3])*opacity/128u)*255u/128u);
    if (!alpha) return;
    const unsigned old_alpha=dst[3];
    const unsigned weight=alpha*255u+old_alpha*(255u-alpha);
    for (unsigned c=0;c<3;++c) {
        const unsigned src=std::min(255u,unsigned(texel[c])*color[c]/128u);
        dst[c]=Byte((src*alpha*255u+unsigned(dst[c])*old_alpha*(255u-alpha)+weight/2)/weight);
    }
    dst[3]=Byte((weight+127)/255);
}

void draw_channel(RasterFrame& frame, const GuestMemory& m, u32 channel,
                  std::span<const TextAtlasResource> resources, std::size_t& pixel_budget,TextLayerParts parts) {
    const u32 pool=m.read_u32(channel);
    const u32 count=m.read_u32(pool+4), capacity=m.read_u32(pool);
    if (count>capacity || count>400) throw std::runtime_error("Invalid source glyph pool count");
    const u32 nodes=m.read_u32(pool+8);
    for (u32 i=0;i<count;++i) {
        const u32 node=nodes+56*i;
        const auto texture=little64(m.bytes(node+48,8));
        // The channel's own FNT texture contains language-specific glyphs.
        // Original CTF artwork and marks use a separate texture descriptor.
        if(parts==TextLayerParts::artwork && (texture&0x3fff)==(m.read_u32(channel+32)&0x3fff) &&
           ((texture>>37)&0x3fff)==0x2e40)continue;
        const float opacity=std::bit_cast<float>(m.read_u32(node+4));
        if (!std::isfinite(opacity) || opacity<0 || opacity>128) throw std::runtime_error("Invalid source glyph opacity");
        if (opacity<1) continue;
        const int x=std::bit_cast<std::int32_t>(m.read_u32(node+12));
        const int y=std::bit_cast<std::int32_t>(m.read_u32(node+16));
        const int x2=std::bit_cast<std::int32_t>(m.read_u32(node+20));
        const int y2=std::bit_cast<std::int32_t>(m.read_u32(node+24));
        const int left=std::max(0,std::min(x,x2)), top=std::max(0,std::min(y,y2));
        const int right=std::min(int(screen_width),std::max(x,x2)), bottom=std::min(int(screen_height),std::max(y,y2));
        if (left>=right || top>=bottom) continue;
        const std::size_t pixels=std::size_t(right-left)*(bottom-top);
        if (pixels>pixel_budget) throw std::runtime_error("Text sprite pixel budget exceeded");
        pixel_budget-=pixels;
        const Atlas atlas=resolve_atlas(m,channel,texture,resources);
        if(frame.rgba.empty())frame.rgba.resize(screen_width*screen_height*4);
        const int u0=uv_pixel(m,node+28,atlas.width), v0=uv_pixel(m,node+32,atlas.height);
        const int u1=uv_pixel(m,node+36,atlas.width), v1=uv_pixel(m,node+40,atlas.height);
        const std::array<Byte,3> color{m.read_u8(node),m.read_u8(node+1),m.read_u8(node+2)};
        const auto sample=[](int p,int start,int end,int first,int last,int size) {
            // Pixel-center sampling handles inverted and stretched source sprites.
            const double fraction=(double(p)+0.5-double(start))/(double(end)-double(start));
            return std::clamp(int(std::floor(first+fraction*(last-first))),0,size-1);
        };
        for (int sy=top;sy<bottom;++sy) {
            const u32 v=sample(sy,y,y2,v0,v1,int(atlas.height));
            for (int sx=left;sx<right;++sx) {
                const u32 u=sample(sx,x,x2,u0,u1,int(atlas.width));
                const u32 pixel=v*atlas.width+u;
                const unsigned index=(atlas.pixels[pixel/2]>>(4*(pixel&1)))&15;
                composite(frame.rgba.data()+4*(sy*screen_width+sx),atlas.palette.data()+4*index,color,unsigned(opacity));
            }
        }
    }
}
}

RasterFrame render_text_layer(const GuestMemory& memory,u32 font,std::span<const TextAtlasResource> resources,TextLayerParts parts) {
    RasterFrame result{screen_width,screen_height,{}};
    if(parts==TextLayerParts::all)result.rgba.resize(screen_width*screen_height*4);
    if (memory.read_u32(font+0x28)) return result;
    std::size_t pixel_budget=8'000'000;
    draw_channel(result,memory,memory.read_u32(font+8),resources,pixel_budget,parts);
    draw_channel(result,memory,memory.read_u32(font+12),resources,pixel_budget,parts);
    return result;
}
}
