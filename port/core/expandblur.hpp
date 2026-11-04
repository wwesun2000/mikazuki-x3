#pragma once
#include <array>
#include <cstdint>
#include <span>
namespace kx3 {
class GuestMemory;
struct BlurSprite {std::array<float,4> uv{};unsigned alpha=0;};
using BlurDraw=std::array<BlurSprite,21>;
// Screen transitions occupy heap+1000..19FF; keep all ten 388-byte
// mode-zero blur payloads disjoint even when both schedulers are full.
inline constexpr std::uint32_t blur_payload(std::uint32_t heap,unsigned slot){return heap+0x2000+400*slot;}
std::uint32_t create_expandblur(GuestMemory&,std::uint32_t heap,std::uint32_t factory,std::span<const std::uint32_t> args);
void update_expandblur(GuestMemory&,std::uint32_t task,std::uint32_t callback);
void release_expandblur(GuestMemory&,std::uint32_t task);
BlurDraw draw_expandblur(const GuestMemory&,std::uint32_t task);
}
