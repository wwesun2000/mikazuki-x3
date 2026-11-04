#pragma once

#include <cstdint>

namespace kx3 {
class GuestMemory;

// SLPM_664.52 SHA256 50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160.
// Entry recognition does not imply a singleton's cold constructor is supported.
[[nodiscard]] bool has_manager_op(std::uint32_t entry) noexcept;
// gp is an explicit original guest register value. A caller using the fixed
// source image may pass its .reginfo gp=0x23DAF0; no host pointer is substituted.
// Source-void results use host placeholder 0 only when v0 is actually undefined.
[[nodiscard]] std::uint64_t invoke_manager_ops(
    GuestMemory& memory, std::uint32_t entry, std::uint32_t self,
    std::uint64_t a1 = 0, std::uint64_t a2 = 0, std::uint64_t a3 = 0,
    std::uint32_t gp = 0);
}
