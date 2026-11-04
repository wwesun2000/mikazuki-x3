#pragma once

#include <cstdint>

namespace kx3 {
class GuestMemory;

// Original 0x0016C540. The caller owns the current initialization transaction.
void initialize_font_cursor(GuestMemory& memory, std::uint32_t font);
}
