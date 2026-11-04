#pragma once
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace kx3 {
class GuestMemory;
enum class CircleSource { current, saved, mask, solid };
struct CirclePass {
    CircleSource source{};
    unsigned test{},depth{},alpha{},palette{};
    std::array<float,4> xy{};
};
using CircleDraw=std::vector<CirclePass>;
inline std::uint32_t circle_payload(std::uint32_t heap,unsigned slot){return heap+0x3000+64*slot;}
std::uint32_t create_circlemask(GuestMemory&,std::uint32_t heap,std::span<const std::uint32_t>);
void update_circlemask(GuestMemory&,std::uint32_t task);
void release_circlemask(GuestMemory&,std::uint32_t task);
CircleDraw draw_circlemask(const GuestMemory&,std::uint32_t task);
}
