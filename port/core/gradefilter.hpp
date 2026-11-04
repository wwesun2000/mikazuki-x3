#pragma once
#include <array>
#include <cstdint>
#include <span>
namespace kx3 {
class GuestMemory;
struct GradeColors {std::array<std::uint32_t,4> top{},bottom{};};
std::uint32_t create_gradefilter(GuestMemory&,std::uint32_t heap,std::span<const std::uint32_t>);
void update_gradefilter(GuestMemory&,std::uint32_t task);
void change_gradefilter(GuestMemory&,std::uint32_t task,std::span<const std::uint32_t>);
void release_gradefilter(GuestMemory&,std::uint32_t task);
GradeColors draw_gradefilter(const GuestMemory&,std::uint32_t task);
}
