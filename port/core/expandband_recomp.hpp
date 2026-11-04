#pragma once
#include <array>
#include <cstdint>
#include <optional>

namespace kx3 {
class GuestMemory;
// 1352B8 draws the 135908 black rectangle over the background on these
// paths. The original 135858 supplies its GS ALPHA.FIX coefficient.
std::optional<std::uint32_t> original_background_darkening(const GuestMemory&);

// The two possible sprite calls from effect_expandband.c, in source order.
// Coordinates are in a single 640x224 GS field. Colors use original GS units.
struct ExpandBandDraw {
    bool black_strip=false;
    std::array<float,4> black_xy{};
    std::array<std::uint32_t,4> black_rgba{};
    std::array<float,4> xy{},uv{};
    std::array<std::uint32_t,4> rgba{};
    std::uint32_t texture_base=0,flags=0;
};

std::uint32_t create_expandband(GuestMemory&,std::uint32_t heap,std::uint32_t interval); // 184690
void update_expandband(GuestMemory&,std::uint32_t task); // 184760
void release_expandband(GuestMemory&,std::uint32_t task); // 1848B8
ExpandBandDraw draw_expandband(const GuestMemory&,std::uint32_t task,unsigned physical_field); // 1847A8
}
