#include "text_commands.hpp"
#include "font_preferences.hpp"
#include "guest_memory.hpp"
#include "recovered.hpp"
#include <sstream>
#include <stdexcept>

namespace kx3 {
namespace {
using u32 = std::uint32_t;
using u64 = std::uint64_t;

u64 signed_word(u32 value) {
    return (value & 0x80000000u) ? (0xffffffff00000000ull | value) : value;
}

u32 signed_halfword(u32 value) {
    const u32 low = value & 0xffff;
    return (low & 0x8000u) ? (0xffff0000u | low) : low;
}

u32 manager_instance(GuestMemory& m) {
    return u32(invoke_recovered(m, 0x10fb38, 0));
}

u32 read_operand(GuestMemory& m, u32 script, u32 count) {
    return u32(invoke_recovered(m, 0x10d5d8, script, count));
}

}

u32 font_channel_metric(GuestMemory& m, u32 channel, u32 slot_offset) {
    const auto target = m.read_u32(m.read_u32(channel) + slot_offset);
    // These source virtuals depend on a0 only. Other targets may use live
    // argument registers or call out; require their actual ABI before dispatch.
    switch (target) {
    case 0x1682e8: case 0x1682f0: case 0x168338: case 0x168330:
        return u32(invoke_text_command(m, target, channel, 0, 0));
    default: {
        std::ostringstream error;
        error << "Unrecovered font getter at source address 0x" << std::hex << target;
        throw std::runtime_error(error.str());
    }
    }
}

namespace {
// 169E68. Reload channel pointers at the same source boundaries, including
// after writes. Valid guest objects can alias fields used later in the call.
u64 sync_ruby_position(GuestMemory& m, u32 font) {
    const u32 x = font_channel_metric(m, m.read_u32(font), 0);
    const u32 y = font_channel_metric(m, m.read_u32(font), 4);
    const u32 size = font_channel_metric(m, m.read_u32(font + 4), 8);
    const u64 vertical_offset = invoke_text_command(m, 0x1686d8, m.read_u32(font + 4), 0, 0);
    invoke_text_command(m, 0x1682d8, m.read_u32(font + 4), x, 0);
    invoke_text_command(m, 0x1682e0, m.read_u32(font + 4), y - size + u32(vertical_offset), 0);
    invoke_text_command(m, 0x169e58, font, x - 16u, 0);
    return vertical_offset; // Source setters and final tail preserve the last defined v0.
}
}

void set_font_colors(GuestMemory& m,u32 font,std::array<std::uint8_t,3> foreground,std::array<std::uint8_t,3> background){
    for(u32 lane:{0u,4u}){
        const auto format=m.read_u32(font+lane);
        for(u32 c=0;c<3;++c){m.write_u8(format+28+c,foreground[c]);m.write_u8(format+32+c,background[c]);}
    }
}
bool has_text_command(u32 entry) noexcept {
    switch (entry) {
    case 0x111550: case 0x122bf0: case 0x122da0: case 0x122dd0: case 0x127240: case 0x1287d0:
    case 0x1284f8: case 0x128af0:
    case 0x129398: case 0x1296c0: case 0x129998: case 0x129c98: case 0x12acb0: case 0x12b028:
    case 0x1682d8: case 0x1682e0: case 0x1682e8: case 0x1682f0:
    case 0x1682f8: case 0x168308: case 0x168330: case 0x168338:
    case 0x1686d8: case 0x169e58: case 0x169e68:
    case 0x16a8c8: case 0x16a950: case 0x175f78: return true;
    default: return false;
    }
}

u64 invoke_text_command(GuestMemory& m, u32 entry, u32 self, u64 a1, u64 a2) {
    switch (entry) {
    case 0x129398:{
        const auto owner=manager_instance(m),font=m.read_u32(owner+0x3c),script=m.read_u32(owner+0x38);
        (void)invoke_recovered(m,0x10d638,script);
        std::array<std::uint8_t,3> color{};
        for(auto& c:color)c=std::uint8_t(read_operand(m,script,1));
        set_font_colors(m,font,color);return 0;
    }
    case 0x128af0: case 0x1284f8: {
        const u32 owner=manager_instance(m),font=m.read_u32(owner+0x3c),script=m.read_u32(owner+0x38);
        if(entry==0x128af0) {
            const auto style=read_operand(m,script,1),size=read_operand(m,script,1);
            set_primary_font_style_size(m,font,style,size); // 16A6B0
        } else {
            const auto spacing=read_operand(m,script,4);
            m.write_u32(m.read_u32(font)+24,spacing); // 16A680 -> 168380
        }
        return 0;
    }
    case 0x175f78: return 0; // Retail ELF: jr ra; daddu v0,zero,zero.
    case 0x111550:
        m.write_u32(self + 0x29c, u32(a1));
        m.write_u32(self + 0x294, 0);
        return 0; // Source void. Does not change +298.
    case 0x127240: {
        const u32 manager = manager_instance(m);
        const u32 script = u32(invoke_recovered(m, 0x1133a8, manager));
        invoke_text_command(m, 0x111550, manager, read_operand(m, script, 1), 0);
        // The retail 175F78(0x12) result is always zero.
        return 0;
    }
    case 0x122da0: case 0x122dd0: // Byte-identical 48-byte slot 0x40 variant.
        m.write_u32(manager_instance(m) + 0x2c0, 1);
        [[fallthrough]]; // Original tail 122BF0 re-fetches the singleton.
    case 0x122bf0:
        m.write_u32(manager_instance(m) + 0x2b4, 1);
        return 0;
    case 0x1287d0: {
        const auto manager = manager_instance(m);
        const auto script = u32(invoke_recovered(m, 0x1133a8, manager));
        m.write_u32(manager + 0x2b8, 1);
        invoke_recovered(m, 0x10d728, script); // Preserve the ruby stream for the glyph worker.
        for (;;) {
            const auto op = read_operand(m, script, 1);
            if (op == 7) return 0;
            if (op == 2) {
                while (read_operand(m, script, 1) != 3)
                    invoke_recovered(m, 0x10d610, script, 1);
            }
        }
    }
    case 0x12acb0: case 0x12b028: {
        const u32 manager = manager_instance(m);
        const u32 script = u32(invoke_recovered(m, 0x1133a8, manager));
        auto duration=read_operand(m,script,4);
        if(entry==0x12b028 && u32(duration)==UINT32_MAX && m.read_u32(manager+0x808))
            duration=m.read_u32(manager+0x810); // 12B050..12B064.
        invoke_recovered(m,entry==0x12b028?0x113808:0x1137f8,manager+0x2e8,duration);
        return 1; // Retail 175F78(0x12) again returns zero.
    }
    case 0x1296c0: {
        const auto manager = manager_instance(m);
        const auto font = u32(invoke_recovered(m, 0x113460, manager));
        const auto script = u32(invoke_recovered(m, 0x1133a8, manager));
        invoke_text_command(m, 0x16a8c8, font, read_operand(m, script, 1), 0);
        return 0;
    }
    case 0x129998: case 0x129c98: {
        const u32 manager = manager_instance(m);
        const u32 font = u32(invoke_recovered(m, 0x113460, manager));
        const u32 script = u32(invoke_recovered(m, 0x1133a8, manager));
        const u32 x = read_operand(m, script, 2);
        const u32 y = read_operand(m, script, 2);
        if (entry == 0x129998)
            invoke_text_command(m, 0x16a8c8, font, signed_halfword(x), signed_halfword(y));
        else
            invoke_text_command(m, 0x16a950, font, x, y);
        return 0;
    }
    case 0x16a8c8: case 0x16a950: {
        const bool relative = entry == 0x16a8c8;
        invoke_text_command(m, relative ? 0x1682f8 : 0x1682d8, m.read_u32(self), a1, 0);
        invoke_text_command(m, relative ? 0x168308 : 0x1682e0, m.read_u32(self), a2, 0);
        return sync_ruby_position(m, self);
    }
    case 0x169e68: return sync_ruby_position(m, self);
    case 0x1682e8: return signed_word(m.read_u32(self + 4));
    case 0x1682f0: return signed_word(m.read_u32(self + 8));
    case 0x168330: return signed_word(m.read_u32(self + 0x10));
    case 0x168338: return signed_word(m.read_u32(self + 0xc));
    case 0x1686d8: return signed_word(m.read_u32(self + 0x24));
    case 0x1682d8: m.write_u32(self + 4, u32(a1)); return 0;
    case 0x1682e0: m.write_u32(self + 8, u32(a1)); return 0;
    case 0x1682f8: m.write_u32(self + 4, m.read_u32(self + 4) + u32(a1)); return 0;
    case 0x168308: m.write_u32(self + 8, m.read_u32(self + 8) + u32(a1)); return 0;
    case 0x169e58: m.write_u32(self + 0x24, u32(a1)); return 0;
    default: throw std::runtime_error("Unported source text command");
    }
}
}
