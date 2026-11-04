#pragma once
#include <cstdint>
namespace kx3 {
class GuestMemory;
struct ExecutionServices;
std::uint32_t create_snow_particles(GuestMemory&,std::uint32_t count,std::uint32_t wind,ExecutionServices*);
void update_snow_particles(GuestMemory&,std::uint32_t task,ExecutionServices*);
std::uint32_t snow_particle_count(const GuestMemory&,std::uint32_t task);
}
