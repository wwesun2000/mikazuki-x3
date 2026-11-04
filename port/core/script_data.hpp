#pragma once

#include <cstdint>

namespace kx3 {
class GuestMemory;

// Recovered from SLPM_664.52, SHA-256:
// 50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160
// Evidence: analysis/ghidra/{scriptdata-readers-v1,scriptdata-all-v1}/functions/*.json.
// Returns the original low 64-bit v0 where the function defines it. For source
// void functions that leave v0 untouched, returns the host API placeholder 0;
// this is not an assertion that the original machine function returned zero.
// Unsupported entry points/dependencies throw before any guest write.
[[nodiscard]] std::uint64_t invoke_script_data(
    GuestMemory& memory, std::uint32_t entry, std::uint32_t self,
    std::uint64_t a1, std::uint64_t a2, std::uint64_t a3 = 0);
}
