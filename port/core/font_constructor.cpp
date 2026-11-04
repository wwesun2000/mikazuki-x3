#include "font_constructor.hpp"
#include "font_cursor.hpp"
#include "font_preferences.hpp"
#include "font_resource.hpp"
#include "guest_memory.hpp"

namespace kx3 {
namespace {
using u32 = std::uint32_t;
using u64 = std::uint64_t;

// Native reserved-heap backend for the original font allocator 1686E0.
// Keep the underlying bytes, including object padding and unused glyphs.
struct FontArena {
    u32 next, end;
    u32 allocate(u32 bytes) {
        const u64 begin = (u64(next) + 63) & ~u64(63);
        const u64 past = (begin + bytes + 63) & ~u64(63);
        if (past > end) throw std::runtime_error("Font object arena exhausted");
        next = u32(past);
        return u32(begin);
    }
};

// 168190 followed by 168430/168600. Only the six stored color bytes change.
u32 make_channel(GuestMemory& m, FontArena& arena, bool ruby) {
    const u32 channel = arena.allocate(ruby ? 0x28 : 0x24);
    m.write_u32(channel, ruby ? 0x225f18 : 0x225ef0);
    for (u32 offset : {4u, 8u, 12u, 20u, 24u}) m.write_u32(channel + offset, 0);
    m.write_u32(channel + 16, ruby ? 1 : 0);
    for (u32 i = 0; i < 3; ++i) {
        m.write_u8(channel + 0x1c + i, 0x80);
        m.write_u8(channel + 0x20 + i, 0);
    }
    if (ruby) m.write_u32(channel + 0x24, 0);
    return channel;
}

// 168810 -> 169B78 -> 169D10. The 56-byte glyph records and 4-bit atlas
// pixels are allocated here. Neither buffer is cleared by its constructor.
u32 make_atlas(GuestMemory& m, FontArena& arena, u32 channel, u32 width, u32 capacity) {
    const u32 atlas = arena.allocate(0x30);
    const u32 pool = arena.allocate(0x10);
    m.write_u32(pool, capacity);
    m.write_u32(pool + 4, 0);
    m.write_u32(pool + 8, arena.allocate(capacity * 0x38));
    const u32 iterator = arena.allocate(0x10);
    m.write_u32(iterator, 0x225f40);
    m.write_u32(iterator + 4, pool);
    m.write_u32(pool + 12, iterator);
    m.write_u32(atlas, pool);
    m.write_u32(atlas + 4, channel);
    m.write_u32(atlas + 8, m.read_u32(0x236eec));
    m.write_u32(atlas + 12, 0);
    m.write_u32(atlas + 0x10, width);
    m.write_u32(atlas + 0x14, width);
    const u32 bytes = width * width / 2;
    m.write_u32(atlas + 0x18, bytes);
    m.write_u32(atlas + 0x1c, arena.allocate(bytes));
    m.write_u32(atlas + 0x20, 0x1680);
    // 168968 resets atlas pointers and the pool count; 16A830 repeats this
    // before anything has been inserted.
    m.write_u32(atlas + 0x24, 0);
    m.write_u32(atlas + 0x28, 0);
    m.write_u32(atlas + 0x2c, 0);
    return atlas;
}

u32 make_stack(GuestMemory& m, FontArena& arena, u32 capacity) { // 16BB70
    const u32 stack = arena.allocate(12);
    m.write_u32(stack, capacity);
    m.write_u32(stack + 8, arena.allocate(capacity * 4));
    m.write_u32(stack + 4, 0);
    return stack;
}

bool valid_heap_range(u32 begin, u64 end) {
    // Protect the ELF, BSS globals and the font's fixed palette/wait indicators.
    return begin >= 0x240000 && begin < end && end <= GuestMemory::size &&
        (end <= 0x1e44100 || begin >= 0x1e444f0);
}
}

FontConstruction construct_font_object(GuestMemory& destination, u32 begin, u32 end,
                                       u32 descriptor, std::span<const std::uint8_t> file) {
    const u64 file_end = u64(descriptor) + file.size();
    if (destination.transaction_active() || !valid_heap_range(begin, end) ||
        !valid_heap_range(descriptor, file_end) || (descriptor < end && begin < file_end))
        throw std::invalid_argument("Invalid guest reservations for font construction");
    GuestMemory m;
    m.write_bytes(0, destination.bytes(0, GuestMemory::size));
    FontArena arena{begin, end};
    const u32 font = arena.allocate(0x38);
    install_font_resource(m, descriptor, file);              // 16BD30
    m.write_u32(0x238858, font);                             // 16C168
    initialize_native_font_palette(m);                       // 16C280
    initialize_font_cursor(m, font);                         // 16C540
    const u32 primary = make_channel(m, arena, false);
    const u32 ruby = make_channel(m, arena, true);
    m.write_u32(font, primary);
    m.write_u32(font + 4, ruby);
    m.write_u32(font + 8, make_atlas(m, arena, primary, 512, 400));
    m.write_u32(font + 12, make_atlas(m, arena, ruby, 256, 100));
    m.write_u32(font + 0x2c, make_stack(m, arena, 2));
    m.write_u32(font + 0x30, make_stack(m, arena, 3));
    m.write_u32(font + 0x34, make_stack(m, arena, 2));
    m.write_u32(font + 0x20, 0);
    m.write_u32(font + 0x28, 0);
    const auto primary_size = m.read_u32(descriptor + 0x10);
    set_primary_font_style_size(m, font, 0, primary_size);   // 16A758, 16A6B0
    auto ruby_size = m.read_u32(descriptor + 0x14);          // 16BF98, 16A770
    if (!ruby_size) ruby_size = primary_size;
    if (ruby_size != 0xff) m.write_u32(ruby + 12, ruby_size);
    // 16AA98's foreground/background values already match both new channels.
    reset_font_position(m, font);                           // 16A860
    m.write_u32(primary + 0x14, 0);                          // 16A650
    m.write_u32(primary + 0x18, 6);                          // 16A680
    destination.replace_contents(std::move(m));
    return {font, arena.next};
}
}
