#pragma once
#include <cstdint>
#include <array>

namespace kx3 {
class GuestMemory;
// Original 16A9F0 sets RGB on both formatters without touching either alpha byte.
void set_font_colors(GuestMemory&,std::uint32_t font,std::array<std::uint8_t,3> foreground,
                     std::array<std::uint8_t,3> background={});
// Read slots 0/1/2/3 of the source font format's getter vtable.
std::uint32_t font_channel_metric(GuestMemory&, std::uint32_t channel, std::uint32_t slot_offset);
bool has_text_command(std::uint32_t entry) noexcept;
std::uint64_t invoke_text_command(GuestMemory& memory, std::uint32_t entry,
                                  std::uint32_t self, std::uint64_t a1, std::uint64_t a2);
}
