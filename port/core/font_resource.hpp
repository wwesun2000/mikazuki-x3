#pragma once
#include "guest_memory.hpp"

namespace kx3 {
struct FontResourceResult {
    std::uint32_t descriptor,groups,glyphs;
};
// Ready file-slot 4 boundary for 16BD30. The caller supplies its reserved
// guest allocation and the original encoded bytes from the asset provider.
FontResourceResult install_font_resource(GuestMemory&,std::uint32_t descriptor,
                                        std::span<const std::uint8_t> file);
// 16C280's source RGBA table. The native renderer consumes its 16 entries
// directly from RAM in place of the PS2 GIF/DMA palette upload.
void initialize_native_font_palette(GuestMemory&);
}
