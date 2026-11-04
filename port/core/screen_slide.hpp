#pragma once
#include <array>
#include <cstdint>
#include <span>
namespace kx3 {
class GuestMemory;
using SlideDraw=std::array<std::array<float,4>,2>; // Original draw order. 18AEF8 draws saved, then current.
std::uint32_t create_screen_slide(GuestMemory&,std::uint32_t heap,std::span<const std::uint32_t> args,
                                 std::uint32_t factory=0x18b040);
void update_screen_slide(GuestMemory&,std::uint32_t task);
void release_screen_slide(GuestMemory&,std::uint32_t task);
SlideDraw draw_screen_slide(const GuestMemory&,std::uint32_t task);
std::uint32_t reserve_mode_two_task(GuestMemory&);
std::uint32_t screen_transition_service(GuestMemory&,std::uint32_t entry,std::uint32_t task);
}
