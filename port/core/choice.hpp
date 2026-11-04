#pragma once

#include <cstdint>

namespace kx3 {
class GuestMemory;

// Closed, original-machine-code choice accessors/predicates only.
// This does not implement navigation, preview, confirmation or external effects.
// For 117D00, v0 is undefined in the source: host placeholder 0, compare memory.
// Every other supported entry returns the original low-64-bit v0.
// Unsupported entries throw before writes; no callbacks are silently skipped.
[[nodiscard]] std::uint64_t invoke_choice_leaf(
    GuestMemory& memory, std::uint32_t entry, std::uint32_t self,
    std::uint64_t a1 = 0);
}
