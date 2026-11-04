#include "font_cursor.hpp"
#include "guest_memory.hpp"

namespace kx3 {
void initialize_font_cursor(GuestMemory& memory, std::uint32_t font) {
    constexpr std::uint32_t records = 0x01e44200;
    constexpr std::uint32_t table = 0x00208128;
    memory.write_u32(0x0023885c, font);

    // 16C57C..16C5BC. Words +A8 and +B0 retain their incoming values.
    for (unsigned i = 0; i < 4; ++i) {
        const auto record = records + i * 0xbc;
        for (const auto offset : {0u, 0xb8u, 0x18u, 4u, 8u, 0xcu, 0x10u, 0x14u, 0xacu, 0xb4u})
            memory.write_u32(record + offset, 0);
    }

    // 16C608..16C6DC. Each source record contains two sets of interleaved
    // pairs. The destination holds each member in a separate 8-word array.
    for (unsigned i = 0; i < 4; ++i) {
        const auto source = table + i * 0x8c;
        const auto record = records + i * 0xbc;
        memory.write_u32(record + 0x20, memory.read_u32(source + 4));
        memory.write_u32(record + 0x1c, memory.read_u32(source));
        for (unsigned j = 0; j < 8; ++j) {
            memory.write_u32(record + 0x44 + j * 4, memory.read_u32(source + 0x0c + j * 8));
            memory.write_u32(record + 0x24 + j * 4, memory.read_u32(source + 0x08 + j * 8));
        }
        memory.write_u32(record + 0x64, memory.read_u32(source + 0x48));
        for (unsigned j = 0; j < 8; ++j) {
            memory.write_u32(record + 0x88 + j * 4, memory.read_u32(source + 0x50 + j * 8));
            memory.write_u32(record + 0x68 + j * 4, memory.read_u32(source + 0x4c + j * 8));
        }
    }
}
}
