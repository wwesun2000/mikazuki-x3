#pragma once
#include "raster_frame.hpp"
#include <cstdint>
#include <span>

namespace kx3 { class GuestMemory; }
namespace kx3::platform {
// Original 4-bit CTF upload bytes, including the 128-byte source header.
// A caller binds only verified resources from the game's asset directory.
struct TextAtlasResource {
    std::uint32_t index;
    std::span<const std::uint8_t> encoded;
};
enum class TextLayerParts { all, artwork };
// Logical 640x448 primary/ruby layer. Reads the committed node pools, so a
// checkpoint restore also restores the visible contents without replaying text.
RasterFrame render_text_layer(const GuestMemory& memory, std::uint32_t font,
                              std::span<const TextAtlasResource> resources = {},
                              TextLayerParts parts=TextLayerParts::all);
}
