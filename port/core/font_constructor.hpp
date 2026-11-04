#pragma once
#include <cstdint>
#include <span>

namespace kx3 {
class GuestMemory;
struct FontConstruction {
    std::uint32_t font;
    std::uint32_t arena_used_end;
};

// 110660's 1686E0(0x38) and 16A098. The caller reserves an object arena
// and a disjoint file-slot-4 destination, and publishes manager+3C only
// after success. Both must be free of other live guest allocations.
FontConstruction construct_font_object(GuestMemory&, std::uint32_t arena_begin,
    std::uint32_t arena_end, std::uint32_t descriptor, std::span<const std::uint8_t> file);
}
