#pragma once
#include <array>
#include <cstdint>
#include <span>
namespace kx3 {
class GuestMemory;
struct ZoomDraw {std::array<float,4> xy{},uv{};};
std::uint32_t create_screen_zoom(GuestMemory&,std::uint32_t heap,std::uint32_t factory,
                                 std::span<const std::uint32_t> args);
void update_screen_zoom(GuestMemory&,std::uint32_t task,std::uint32_t callback);
void release_screen_zoom(GuestMemory&,std::uint32_t task);
ZoomDraw draw_screen_zoom(const GuestMemory&,std::uint32_t task);
}
