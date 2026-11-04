#pragma once
#include "guest_memory.hpp"
#include <array>
#include <span>
#include <vector>

namespace kx3 {
struct WindSprite {std::array<float,4> xy,uv;unsigned alpha;};
inline constexpr std::uint32_t wind_work_begin=0x14ec000,wind_work_stride=0x1420;
inline constexpr std::uint32_t wind_work_end=wind_work_begin+10*wind_work_stride;
inline std::uint32_t wind_payload(unsigned slot){
    // The ten mode-zero task arenas end at 14EC000. The ten mode-two
    // work areas fit below the original 1500000 font arena.
    if(slot>=10)throw std::runtime_error("Wind task slot outside original pool");
    return wind_work_begin+slot*wind_work_stride;
}
std::uint32_t create_screen_wind(GuestMemory&,std::uint32_t heap,std::span<const std::uint32_t>);
void update_screen_wind(GuestMemory&,std::uint32_t task);
void release_screen_wind(GuestMemory&,std::uint32_t task);
std::vector<WindSprite> draw_screen_wind(const GuestMemory&,std::uint32_t task);
}
