#pragma once
#include <cstdint>

namespace kx3 {
class GuestMemory;
struct ExecutionServices;
void install_scenario_checkpoint(GuestMemory&);
void advance_record_timer(GuestMemory&);
bool has_checkpoint_writer(std::uint32_t entry);
std::uint64_t checkpoint_writer(GuestMemory&,std::uint32_t entry,std::uint32_t out,std::uint32_t extra);
std::uint64_t write_scenario_checkpoint(GuestMemory&,ExecutionServices*);
}
