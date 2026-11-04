#pragma once
#include "guest_memory.hpp"
#include <cstdint>
#include <span>
#include <vector>

namespace kx3 {
struct ScriptImageIndex {
    std::uint32_t self, image, block_count, label_count, labels, end;
};
// Build the original relocated SCR/label tables directly from ScenarioLink.
// This is a data-loader component, NOT the full10CAF0 constructor: no manager,
// fonts, progress buffers or initial10D868 transition are fabricated.
// The caller explicitly reserves [begin,end) in the guest address space.
// Fresh host allocation uses existing RAM bytes; it does not silently promise
// that the original PS2 allocators zero-initialized their payloads.
ScriptImageIndex load_script_index(GuestMemory&, std::span<const std::uint8_t>,
                                  std::uint32_t begin, std::uint32_t end);
}
