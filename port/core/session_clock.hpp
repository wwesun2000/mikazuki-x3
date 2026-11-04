#pragma once
#include <cstdint>

namespace kx3 {
class GuestMemory;
struct ExecutionServices;
void initialize_clock_and_pad(GuestMemory&,std::uint32_t counter);
float source_random_range(GuestMemory&,float low,float high,ExecutionServices*);
std::uint32_t source_random_word(GuestMemory&,ExecutionServices*);
}
