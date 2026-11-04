#pragma once
#include "recovered.hpp"

namespace kx3 {
bool has_timechart_native(std::uint32_t);
std::uint64_t invoke_timechart_native(GuestMemory&,std::uint32_t entry,
                                      std::uint32_t a0,std::uint64_t a1,ExecutionServices*);
void sample_chart_directions(GuestMemory&,std::uint16_t held);
std::uint16_t chart_direction_repeat(GuestMemory&);
bool chart_save_indices(GuestMemory&,std::uint32_t& first,std::uint32_t& second);
}
