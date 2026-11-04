#pragma once
#include "guest_memory.hpp"
#include <array>
#include <span>
#include <vector>

namespace kx3 {
struct ScreenWipe {
    std::uint32_t factory,update,draw,release,bytes,source_file,source_line;
};
inline constexpr ScreenWipe screen_wipes[]={
    {0x18bc40,0x18bef8,0x18c1c0,0x18c320,0x24,0x22f2d8,0x69},
    {0x18ce40,0x18d028,0x18d250,0x18d5b0,0x1c,0x22f3a8,0x67},
    {0x18d5c8,0x18d7c8,0x18d9f0,0x18dd38,0x1c,0x22f3c0,0x66},
    {0x18f730,0x18f9c0,0x18fc58,0x18ff78,0x1410,0x22f458,0x6b},
    {0x18ff90,0x1900b0,0x190220,0x1904b8,0x18,0x22f470,0x66},
};
inline const ScreenWipe* screen_wipe(std::uint32_t pc){
    for(const auto& w:screen_wipes)
        if(pc==w.factory || pc==w.update || pc==w.draw || pc==w.release ||
           (pc==0x190190 && w.factory==0x18ff90))return &w;
    return nullptr;
}
struct WipeSprite {
    enum class Source {current,saved,clear} source;
    std::array<float,4> xy,uv;
    unsigned alpha;
};
std::uint32_t create_screen_wipe(GuestMemory&,std::uint32_t,std::span<const std::uint32_t>,const ScreenWipe&);
void advance_screen_wipe(GuestMemory&,std::uint32_t task,std::uint32_t pc);
std::vector<WipeSprite> draw_screen_wipe(const GuestMemory&,std::uint32_t task);
}
