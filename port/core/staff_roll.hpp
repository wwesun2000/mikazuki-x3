#pragma once
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace kx3 {
class GuestMemory;
struct ExecutionServices;
namespace credits {
using u32=std::uint32_t;
// Native storage immediately after the SAB cache. Original pointer globals,
// fourteen row records, temporary tokens and line surfaces remain guest data.
constexpr u32 file_size=0x19b0000, file_ready=file_size+4, edition=file_size+8;
constexpr u32 source=0x19b2000, copy=0x19b4800, surfaces=0x19b8000;
constexpr u32 packet=0x19e8000, stack=0x19ff000;
constexpr u32 first_row=0x23ead0, live_cursor=0x2387e4;
struct Line {
    u32 offset;
    std::string original;
    int x,y,size,alignment,anchor;
};
void install(GuestMemory&,std::span<const std::uint8_t> file,u32 program);
void remember_line(GuestMemory&,u32 slot,u32 offset,u32 cursor,bool continued,bool align);
std::vector<Line> visible_lines(const GuestMemory&);
void advance(GuestMemory&,ExecutionServices*);
}
}
