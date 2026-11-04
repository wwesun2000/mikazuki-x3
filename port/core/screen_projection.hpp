#pragma once
#include <array>
#include <cstdint>
namespace kx3 {
class GuestMemory;
std::array<float,2> clip_screen_point(const GuestMemory&,std::array<float,2>); // 192478
std::array<float,2> screen_project_point(GuestMemory&,float angle); // 1925F8
std::uint32_t screen_sector_for_y(const GuestMemory&,float angle,float projected_y); // 192810 after 1925F8
std::uint32_t screen_project_sector(GuestMemory&,float angle); // 192810
}
