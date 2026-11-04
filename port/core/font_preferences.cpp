#include "font_preferences.hpp"
#include "recovered.hpp"
#include "text_commands.hpp"
#include <bit>

namespace kx3 {
namespace {
using u32 = std::uint32_t;

u32 current_font(GuestMemory& m, u32 manager) {
    const auto font = u32(invoke_recovered(m, 0x113460, manager));
    if (!font) throw std::runtime_error("Missing original font object from 0x0016a098 at manager+0x3c");
    return font;
}

// 16A4A0 and 16A570 check BOTH old origin coordinates before overwriting one.
// On the clamp path the original performs the virtual read again after the write.
void set_origin(GuestMemory& m, u32 font, u32 axis, u32 value) {
    const bool at_origin = font_channel_metric(m, m.read_u32(font), 0) == m.read_u32(font + 16)
                        && font_channel_metric(m, m.read_u32(font), 4) == m.read_u32(font + 20);
    const u32 primary = m.read_u32(font);
    m.write_u32(font + 16 + axis, value);
    const u32 position = font_channel_metric(m, primary, axis);
    if (std::bit_cast<std::int32_t>(position) < std::bit_cast<std::int32_t>(value)) {
        m.write_u32(m.read_u32(font) + 4 + axis, value);
        invoke_text_command(m, 0x169e68, font, 0, 0);
    }
    if (at_origin) reset_font_position(m, font);
}

std::uint64_t apply_preferences(GuestMemory& m) {
    const auto manager = u32(invoke_recovered(m, 0x10fb38, 0));
    const auto font = current_font(m, manager);
    const auto script = u32(invoke_recovered(m, 0x1133a8, manager));
    const auto pref = manager + 0x308;

    set_primary_font_style_size(m, font, 0, 0);
    m.write_u32(m.read_u32(font) + 16, 0); // 16A740 -> 1684F0 -> 168318

    // Each of 113B30/98/D0 and 113C08 looks up the manager and font again.
    const auto preference_font = [&] { return current_font(m, u32(invoke_recovered(m, 0x10fb38, 0))); };
    const auto layout = preference_font();
    set_origin(m, layout, 0, m.read_u32(pref + 8));
    m.write_u32(layout + 24, 640u - m.read_u32(pref + 12)); // 16A490
    set_origin(m, layout, 4, m.read_u32(pref + 4));
    m.write_u32(layout + 28, 448u - m.read_u32(pref + 16)); // 16A640
    const auto letter = preference_font();
    m.write_u32(m.read_u32(letter) + 20, m.read_u32(pref + 28)); // 16A650 -> 168390
    const auto line = preference_font();
    m.write_u32(m.read_u32(line) + 24, m.read_u32(pref + 24)); // 16A680 -> 168380
    const auto ruby = m.read_u32(preference_font() + 4);
    const auto offset = std::bit_cast<std::int8_t>(m.read_u8(pref + 32));
    m.write_u32(ruby + 36, u32(std::int32_t(offset))); // 16AF30 -> 1686D0

    const auto alpha = m.read_u32(0x235f8c); // ELF f12 bits, 16B7B0 -> 169B08
    m.write_u32(m.read_u32(font + 8) + 8, alpha);
    m.write_u32(m.read_u32(font + 12) + 8, alpha);
    m.write_u32(m.read_u32(font + 8) + 12, 0); // 16B7F0 -> 169B10
    m.write_u32(m.read_u32(font + 12) + 12, 0);
    const auto label = invoke_recovered(m, 0x10d748, script);
    const auto seen = invoke_recovered(m, 0x10ef18, script, label);
    const bool enable = !seen && !m.read_u32(manager + 0x740);
    m.write_u32(manager + 0x2a4, enable ? 1 : 0); // Source tails 1126C0 and 1126D0
    return seen;
}
}

void set_primary_font_style_size(GuestMemory& m, u32 font, u32 style, u32 size) {
    // 168318 and 168340 use 255 as "leave existing field", including
    // when that sentinel comes from 16BF88's file descriptor at +16.
    if (style != 255) m.write_u32(m.read_u32(font) + 16, style);
    const auto primary = m.read_u32(font);
    if (!size) {
        const u32 descriptor = m.read_u32(0x236f30);
        if (!descriptor) throw std::runtime_error("0x0016bf88 requires the installed font descriptor");
        size = m.read_u32(descriptor + 16);
    }
    if (size != 255) m.write_u32(primary + 12, size);
}

void reset_font_position(GuestMemory& m, u32 font) {
    const u32 x = m.read_u32(font + 16);
    const u32 y = m.read_u32(font + 20);
    m.write_u32(m.read_u32(font) + 4, x);
    m.write_u32(m.read_u32(font) + 8, y);
    invoke_text_command(m, 0x169e68, font, 0, 0);
    m.write_u32(font + 32, 0);
}

std::uint64_t apply_page_font_preferences(GuestMemory& m) {
    if (m.transaction_active()) return apply_preferences(m);
    GuestMemory::Transaction tx(m);
    const auto result = apply_preferences(m);
    tx.commit();
    return result;
}

std::uint64_t apply_script_font_margin(GuestMemory& m,std::uint64_t opcode) {
    const auto owner = u32(invoke_recovered(m,0x10fb38,0)), font = current_font(m,owner);
    const auto script = u32(invoke_recovered(m,0x1133a8,owner));
    const auto margin = u32(invoke_recovered(m,0x10d5d8,script,4));
    switch (opcode) {
    case 0x5d: set_origin(m,font,0,margin); break;
    case 0x5f: m.write_u32(font+24,640u-margin); break;
    case 0x61: set_origin(m,font,4,margin); break;
    case 0x63: m.write_u32(font+28,448u-margin); break;
    }
    return 0;
}

std::uint64_t apply_script_font_preference(GuestMemory& m,std::uint64_t opcode) {
    const auto owner = u32(invoke_recovered(m,0x10fb38,0)), font = current_font(m,owner);
    const auto script = m.read_u32(owner + 0x38);
    auto setting = [&](u32 bytes,u32 offset) {
        const auto value = u32(invoke_recovered(m,0x10d5d8,script,bytes));
        m.write_u32(owner + offset,value);
        return value;
    };
    switch (opcode) {
    case 0x41: (void)invoke_recovered(m,0x111550,owner,setting(1,0x31c)); break;
    case 0x45: {
        const auto value = std::bit_cast<std::int8_t>(std::uint8_t(setting(1,0x328)));
        m.write_u32(m.read_u32(font+4)+36,u32(std::int32_t(value)));
        break;
    }
    case 0x54: m.write_u32(m.read_u32(font)+20,setting(4,0x324)); break;
    case 0x56: m.write_u32(m.read_u32(font)+24,setting(4,0x320)); break;
    case 0x5e: set_origin(m,font,0,setting(4,0x310)); break;
    case 0x60: m.write_u32(font+24,640u-setting(4,0x314)); break;
    case 0x62: set_origin(m,font,4,setting(4,0x30c)); break;
    case 0x64: m.write_u32(font+28,448u-setting(4,0x318)); break;
    }
    return 0;
}
}
