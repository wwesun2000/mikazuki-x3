#pragma once
#include "screen_zoom.hpp"
#include <array>
namespace kx3 {
struct ExecutionServices;
struct ShakeDraw {std::array<ZoomDraw,2> sprites{};bool visible=false;};
std::uint32_t create_screen_shake(GuestMemory&,std::uint32_t heap,std::span<const std::uint32_t>);
void update_screen_shake(GuestMemory&,std::uint32_t task,ExecutionServices*);
void release_screen_shake(GuestMemory&,std::uint32_t task);
ShakeDraw draw_screen_shake(const GuestMemory&,std::uint32_t task);
}
