#pragma once
#include "screen_zoom.hpp"
#include <vector>
namespace kx3 {
std::uint32_t create_screen_ripple(GuestMemory&,std::span<const std::uint32_t> args);
void update_screen_ripple(GuestMemory&,std::uint32_t task);
void release_screen_ripple(GuestMemory&,std::uint32_t task);
std::vector<ZoomDraw> draw_screen_ripple(const GuestMemory&,std::uint32_t task);
}
