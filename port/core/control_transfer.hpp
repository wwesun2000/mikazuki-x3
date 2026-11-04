#pragma once
#include <cstdint>
namespace kx3 {
class GuestMemory;
struct ExecutionServices;
std::uint64_t run_vm_context(GuestMemory&,std::uint32_t,std::uint32_t,std::uint64_t,std::uint64_t,std::uint64_t,ExecutionServices*);
void advance_scene_fade(GuestMemory&,ExecutionServices*);
std::uint64_t run_scenario_return(GuestMemory&,std::uint32_t entry,std::uint32_t self,std::uint64_t a1,ExecutionServices*);
bool has_control_transfer(std::uint32_t) noexcept;
std::uint64_t invoke_control_transfer(GuestMemory&,std::uint32_t entry,std::uint32_t self,
                                     std::uint64_t a1,std::uint64_t a2,std::uint64_t a3,
                                     ExecutionServices*);
}
