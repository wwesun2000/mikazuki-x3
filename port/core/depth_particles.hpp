#pragma once
#include <cstdint>
#include <span>
#include <vector>
namespace kx3 {
class GuestMemory;
struct ExecutionServices;
struct DepthParticleSprite {float x=0,y=0,size=0;unsigned alpha=0,light=128;};
std::uint32_t create_depth_particles(GuestMemory&,std::span<const std::uint32_t>,ExecutionServices*);
void update_depth_particles(GuestMemory&,std::uint32_t task,ExecutionServices*);
void release_depth_particles(GuestMemory&,std::uint32_t task);
std::vector<DepthParticleSprite> draw_depth_particles(const GuestMemory&,std::uint32_t task);
}
