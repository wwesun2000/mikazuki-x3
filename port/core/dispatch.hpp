#pragma once
#include <cstdint>

namespace kx3 {
class GuestMemory;
struct ExecutionServices;
// Source-bound default-context methods and manager accessors. See
// analysis/ghidra/vm-execution-chain-v1/functions/<entry>.json.
// Virtual calls use the original guest vtables and the recovered call registry.
std::uint64_t invoke_dispatch(GuestMemory&, std::uint32_t entry,
                             std::uint32_t self, std::uint64_t a1,
                             std::uint64_t a2, std::uint64_t a3, ExecutionServices*);
}
