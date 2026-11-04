#pragma once

#include <cstdint>
#include <vector>

namespace kx3::platform {
// Portable, tightly packed top-to-bottom RGBA8, straight alpha, width * 4 stride.
// No OS handle or renderer ownership. Publish via shared_ptr<const RasterFrame>.
struct RasterFrame {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::vector<std::uint8_t> rgba;
};
}
