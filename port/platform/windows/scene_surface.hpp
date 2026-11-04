#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstdint>

namespace kx3::platform::windows {
inline std::uint32_t scene_pixel(const std::uint8_t* rgba,unsigned y,bool scanlines,unsigned darkening=0){
    const unsigned gain=rgba[3]*(scanlines && (y&1u)?195u:255u);
    // GS ALPHA_1 = 0x64, Cs = black, FIX = darkening. The original
    // rectangle precedes the text/foreground and the PC scanline filter.
    const auto channel=[&](unsigned c){return ((c*(128-darkening))>>7)*gain/65025u;};
    return (channel(rgba[0])<<16)|(channel(rgba[1])<<8)|channel(rgba[2]);
}
inline void draw_scene_surface(HDC dc,RECT s,int width,int height,const std::uint32_t* pixels,bool smooth){
    BITMAPINFO bi{};bi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);bi.bmiHeader.biWidth=width;
    bi.bmiHeader.biHeight=-height;bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;
    SetStretchBltMode(dc,smooth?HALFTONE:COLORONCOLOR);SetBrushOrgEx(dc,0,0,nullptr);
    StretchDIBits(dc,s.left,s.top,s.right-s.left,s.bottom-s.top,0,0,width,height,pixels,&bi,DIB_RGB_COLORS,SRCCOPY);
}
}
