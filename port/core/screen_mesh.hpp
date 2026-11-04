#pragma once
// Original119 crash-wipe callbacks; generated machine-code bodies and explicit host boundaries.
#include "guest_memory.hpp"
#include "recovered.hpp"
#include <array>
#include <span>
#include <vector>
namespace kx3::screen_mesh {
struct Vertex {std::int32_t u,v,x,y,z;};
struct Triangle {std::array<Vertex,3> vertices;unsigned alpha;};
constexpr std::uint32_t mesh_begin=0x1c70000,mesh_stride=0x1b000,mesh_end=mesh_begin+10*mesh_stride;
static_assert(mesh_begin>=0x1be0000+4*0x22000 && mesh_end<0x1e16a40);
static_assert(mesh_stride>=96+25*8*544);
std::uint32_t create(GuestMemory&,std::span<const std::uint32_t>,ExecutionServices* =nullptr);
void update(GuestMemory&,std::uint32_t,ExecutionServices* =nullptr);
void release(GuestMemory&,std::uint32_t);
std::vector<Triangle> draw(const GuestMemory&,std::uint32_t);
}
