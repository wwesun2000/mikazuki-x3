#pragma once

#include <cstdint>

namespace kx3 {
class GuestMemory;

// Source-bound guest routines from SLPM_664.52 (same ELF as script_data.hpp).
// Their names describe recovered behavior; these do not call the host libc.
// Valid guest RAM/string inputs only. Copies retain the source's forward block
// order, including overlap propagation; neither routine promises memmove.
[[nodiscard]] std::uint32_t source_strlen(GuestMemory&, std::uint32_t start); // 1FDC64
[[nodiscard]] std::uint64_t source_strcpy(GuestMemory&, std::uint64_t destination,
                                        std::uint64_t source); // 1FDB50
[[nodiscard]] std::uint64_t source_strcmp(GuestMemory&, std::uint64_t left,
                                        std::uint64_t right); // 1FDA0C
[[nodiscard]] std::uint64_t source_memcpy(GuestMemory&, std::uint64_t destination,
                                        std::uint64_t source, std::uint64_t count); // 1FC524
}
