#pragma once
#include "guest_memory.hpp"
#include <span>
namespace kx3 {
struct ExecutionServices;
std::uint32_t create_mime_effect(GuestMemory&,std::span<const std::uint32_t>,ExecutionServices*);
void update_mime_effect(GuestMemory&,std::uint32_t task,ExecutionServices*);
void change_mime_effect(GuestMemory&,std::uint32_t task,std::span<const std::uint32_t>);
std::uint32_t mime_grid(const GuestMemory&,std::uint32_t task);
}
