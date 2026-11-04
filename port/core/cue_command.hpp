#pragma once
#include "recovered.hpp"

namespace kx3 {
// 138C28 uses a native session semaphore handle in place of the EE kernel handle.
void initialize_cue_queue(GuestMemory&,std::uint32_t semaphore_handle);
bool has_cue_command(std::uint32_t) noexcept;
std::uint64_t invoke_cue_command(GuestMemory&,std::uint32_t entry,std::uint32_t self,
                                 std::uint64_t a1,std::uint64_t a2,ExecutionServices*);
}
