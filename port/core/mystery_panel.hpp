#pragma once
#include <cstdint>
#include <string>
namespace kx3 {
class GuestMemory;
struct ExecutionServices;
namespace mystery {
using u32=std::uint32_t;
constexpr u32 culprit=0x22c218, memory=0x22c490, descriptor=0x2387a8;
constexpr u32 meta=0x1a90000, packet=0x1aa0000, main_file=0x1ac0000, slots=0x1be0000;
constexpr u32 slot_capacity=0x22000, sprite_count=meta+0x200, sprites=meta+0x400, sprite_size=36;
bool active(const GuestMemory&);
u32 file_service(GuestMemory&,ExecutionServices*,u32 entry,u32 address,u32 argument,u32 size,u32 flags);
void advance(GuestMemory&,ExecutionServices*);
void complete_requests(GuestMemory&,ExecutionServices*);
void bind_texture(GuestMemory&,u32 address,u32 format,u32 width,u32 height);
void remember_sprite(GuestMemory&,u32 packet_address,u32 option);
int option_at(const GuestMemory&,int x,int y);
int selected(const GuestMemory&);
unsigned question_number(const GuestMemory&);
}
}
