#pragma once
#include <cstdint>
namespace kx3 {
class GuestMemory;
struct ExecutionServices;
bool has_screen_task(std::uint32_t entry) noexcept;
std::uint64_t invoke_screen_task(GuestMemory&,std::uint32_t entry,std::uint32_t self,std::uint64_t a1,
    ExecutionServices*);
// Update the original mode-2 task slots, preserving their guest handles and
// data. The caller owns the frame transaction and supplies a reserved block
// of 10 x 32 bytes for ordinary effects. The 232-byte 192080 objects are in
// ten separate 256-byte allocations at payloads+0x1000 through +0x19FF.
void tick_screen_tasks(GuestMemory&,std::uint32_t payloads);
}
