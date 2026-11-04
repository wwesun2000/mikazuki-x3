#pragma once
#include "guest_memory.hpp"

namespace kx3 {
// 16A6B0 and 16A860. Like the source leaves, these participate in their caller's transaction.
void set_primary_font_style_size(GuestMemory&, std::uint32_t font, std::uint32_t style,
                                 std::uint32_t size);
void reset_font_position(GuestMemory&, std::uint32_t font);
// Common 12FA88 preference setter used by eight original script opcodes.
std::uint64_t apply_script_font_preference(GuestMemory&, std::uint64_t opcode);
// 12A268 changes the active text area without changing saved preferences.
std::uint64_t apply_script_font_margin(GuestMemory&, std::uint64_t opcode);

// 12F1D0 reads the manager singleton and takes no game arguments.
std::uint64_t apply_page_font_preferences(GuestMemory&);
}
