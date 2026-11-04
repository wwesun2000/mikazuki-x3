#include "script_data.hpp"
#include "guest_memory.hpp"
#include "source_libc.hpp"

#include <stdexcept>

namespace kx3 {
namespace {
// Original 16 closed entry bodies total 532 bytes. Binding digest over ascending
// [LE32 entry, LE32 body_length, body_bytes] records:
// e4b38407681394bb0dd5ce3a96e45da0bb9a6ef4a01a5ec1d850479939e7c60d
// The additional strlen dependency is exported separately in
// analysis/ghidra/reader-dependencies-v1/functions/001fdc64.json.
// The EE's LW, ADDIU, ADDU, SUBU and SLL produce sign-extended 32-bit results
// in the low 64-bit GPR lane. Express bit patterns without signed C++ overflow.
constexpr std::uint64_t sext32(std::uint32_t bits) noexcept {
    return (bits & 0x80000000u) ? (0xffffffff00000000ull | bits) : bits;
}

constexpr std::uint32_t add32(std::uint32_t a, std::uint32_t b) noexcept {
    return a + b;
}

// Original 10D5D8..10D60C / 10D6C8..10D6FC. The bytes are assembled BE even
// though the cursor field and the guest struct itself are stored little-endian.
// Reload and store the cursor each iteration, as the original delay slot does.
std::uint64_t read_be(GuestMemory& memory, std::uint32_t self,
                      std::uint32_t cursor_field, std::uint64_t count) {
    if (count == 0) return 0;
    std::uint32_t iteration = 0;
    std::uint32_t value = 0;
    do {
        const auto cursor = memory.read_u32(add32(self, cursor_field));
        value <<= 8;
        iteration = add32(iteration, 1);
        const auto byte = memory.read_u8(cursor);
        const bool more = sext32(iteration) < count; // original SLTU is 64-bit.
        value |= byte;
        memory.write_u32(add32(self, cursor_field), add32(cursor, 1));
        if (!more) break;
    } while (true);
    return sext32(value); // SLL sign-extends; OR with LBU does not clear high bits.
}

// Original selected block: self + 8 + (load32(self+D0) << 2), then block+430.
std::uint32_t selected_base(GuestMemory& memory, std::uint32_t self) {
    const auto selector = memory.read_u32(add32(self, 0xd0));
    const auto table = add32(self, selector << 2);
    const auto block = memory.read_u32(add32(table, 8));
    return memory.read_u32(add32(block, 0x430));
}

// 10D610..10D634 / 10D788..10D7AC. Do not move the block/base loads before
// the cursor write: the source instruction order matters for aliased memory.
std::uint64_t advance(GuestMemory& memory, std::uint32_t self,
                      std::uint32_t cursor_field, std::uint64_t displacement) {
    const auto selector = memory.read_u32(add32(self, 0xd0));
    const auto old_cursor = memory.read_u32(add32(self, cursor_field));
    const auto table = add32(self, selector << 2);
    const auto cursor = add32(old_cursor, static_cast<std::uint32_t>(displacement));
    memory.write_u32(add32(self, cursor_field), cursor);
    const auto block = memory.read_u32(add32(table, 8));
    const auto base = memory.read_u32(add32(block, 0x430));
    return sext32(cursor - base);
}

// 10D700..10D71C / 10D7B0..10D7CC. Original setters never write v0.
void seek(GuestMemory& memory, std::uint32_t self,
          std::uint32_t cursor_field, std::uint64_t offset) {
    const auto base = selected_base(memory, self);
    memory.write_u32(add32(self, cursor_field), add32(base, static_cast<std::uint32_t>(offset)));
}

// 10E630: history records are two guest words, not a host packed bitfield.
std::uint32_t history_record(GuestMemory& memory, std::uint32_t self,
                             std::uint64_t index) {
    return add32(memory.read_u32(add32(self, 0x138)),
                 static_cast<std::uint32_t>(index) << 3);
}

// 10E748 / 10E8D8 / 10E9D8. Cache word1 before any output store, but reload
// word0 after each possible output store. Output pointers may alias a record.
// The original stack temporary's other bits do not affect the two sentinels.
std::uint64_t unpack_history(GuestMemory& memory, std::uint32_t self,
                             std::uint64_t index, std::uint64_t out_selector,
                             std::uint64_t out_index, bool upper) {
    const auto record = history_record(memory, self, index);
    const auto word1 = memory.read_u32(add32(record, 4));
    const auto selector_shift = upper ? 5u : 0u;
    const auto index_shift = upper ? 14u : 0u;
    const auto selector = (word1 >> selector_shift) & 0x1fu;
    if (out_selector != 0)
        memory.write_u32(static_cast<std::uint32_t>(out_selector), selector);
    if (out_index != 0)
        memory.write_u32(static_cast<std::uint32_t>(out_index),
                          (memory.read_u32(record) >> index_shift) & 0x3fffu);
    const auto current_index = (memory.read_u32(record) >> index_shift) & 0x3fffu;
    return selector != 0x1fu && current_index != 0x3fffu ? 1 : 0;
}

std::uint64_t mark_history(GuestMemory& memory, std::uint32_t self,
                           std::uint64_t index, std::uint32_t word_offset,
                           std::uint32_t mask) {
    const auto record = history_record(memory, self, index);
    const auto field = add32(record, word_offset);
    memory.write_u32(field, memory.read_u32(field) | mask);
    return sext32(record); // Original v0 remains the 10E630 result.
}

// 10F898: the table stores guest pointers; name starts at record+8, offset +4.
std::uint32_t label_record(GuestMemory& memory, std::uint32_t self,
                           std::uint64_t index) {
    const auto table = memory.read_u32(add32(self, 0xcc));
    return memory.read_u32(add32(table, static_cast<std::uint32_t>(index) << 2));
}

// 10F628. Original unsigned bytes, 32-bit SLLV/ADDU, byte-sized counter.
std::uint32_t label_hash(GuestMemory& memory, std::uint32_t text) {
    std::uint32_t value = 0;
    std::uint32_t shift = 0;
    auto byte = memory.read_u8(text);
    while (byte != 0) {
        ++text;
        const auto part = static_cast<std::uint32_t>(byte) << (shift & 31u);
        byte = memory.read_u8(text);
        shift = (shift + 1) & 255u;
        value += part;
    }
    return ((value & 255u) + (value >> 8)) & 255u;
}

std::uint32_t label_bucket(GuestMemory& memory, std::uint32_t self,
                           std::uint64_t selector, std::uint32_t name) {
    const auto hash = label_hash(memory, name);
    const auto block = memory.read_u32(add32(add32(self,
        static_cast<std::uint32_t>(selector) << 2), 8));
    return memory.read_u32(add32(add32(block, hash << 2), 0x30));
}

// 10F820 requires a present label. The original has no failure exit; the host
// reports its invalid-input boundary instead of hanging on a zero stride.
std::uint32_t find_label(GuestMemory& memory, std::uint32_t self,
                         std::uint64_t selector, std::uint32_t name) {
    auto record = label_bucket(memory, self, selector, name);
    for (;;) {
        if (record == 0)
            throw std::runtime_error("10f820 requires a present label: null bucket");
        if (source_strcmp(memory, name, sext32(add32(record, 8))) == 0) return record;
        const auto stride = memory.read_u16(record);
        if (stride == 0)
            throw std::runtime_error("10f820 requires a present label: terminal record mismatch");
        record = add32(record, stride);
    }
}

bool label_exists(GuestMemory& memory, std::uint32_t self,
                   std::uint64_t selector, std::uint32_t name) {
    auto record = label_bucket(memory, self, selector, name);
    if (record == 0) return false;
    for (;;) {
        if (source_strcmp(memory, name, sext32(add32(record, 8))) == 0) return true;
        const auto stride = memory.read_u16(record);
        record = add32(record, stride);
        if (stride == 0) return false;
    }
}

std::uint32_t find_selector(GuestMemory& memory, std::uint32_t self,
                            std::uint32_t name) {
    for (std::uint32_t selector = 0; selector < 32; ++selector) {
        if (memory.read_u32(add32(add32(self, selector << 2), 8)) != 0 &&
            label_exists(memory, self, selector, name)) return selector;
    }
    return 0xffffffffu;
}
}

std::uint64_t invoke_script_data(GuestMemory& memory, std::uint32_t entry,
                                  std::uint32_t self, std::uint64_t a1,
                                  std::uint64_t a2, std::uint64_t a3) {
    switch (entry) {
    case 0x0010d3d0:
    case 0x0010d3e8:
        return sext32(add32(add32(self, static_cast<std::uint32_t>(a1) << 4), 0xe4));
    case 0x0010d4c8:
    case 0x0010d590: {
        const auto destination = add32(add32(self, static_cast<std::uint32_t>(a1) << 4), 0xe4);
        if (sext32(destination) != a2)
            (void)source_strcpy(memory, sext32(destination), a2);
        const auto block = memory.read_u32(add32(add32(self,
            static_cast<std::uint32_t>(a1) << 2), 0xb0));
        const auto encoded = add32(block, 0x434);
        memory.write_u8(encoded, 2);
        for (std::uint32_t i = 0; i < 12; ++i) memory.write_u8(add32(encoded, i + 1), 0x21);
        std::uint32_t i = 0;
        for (;;) {
            // Original calls strlen again on every iteration; padding and
            // previous stores can modify an aliased source string.
            const auto length = source_strlen(memory, static_cast<std::uint32_t>(a2));
            if (sext32(i) >= sext32(length)) break;
            const auto byte = memory.read_u8(add32(static_cast<std::uint32_t>(a2), i));
            memory.write_u8(add32(encoded, i + 1), byte);
            ++i;
        }
        memory.write_u8(add32(encoded, 14), 0x1b);
        memory.write_u8(add32(encoded, 13), 3);
        return 0; // Last 10D54C SLTU result, not an invented void result.
    }
    case 0x0010d5d8: return read_be(memory, self, 0xd8, a1);
    case 0x0010d610: return advance(memory, self, 0xd8, a1);
    case 0x0010d638:
        // Ghidra inferred void, but 10D678 tail-jumps to 10D610, defining v0.
        if ((read_be(memory, self, 0xd8, 1) & 0xffu) == 0)
            (void)advance(memory, self, 0xd8, 2);
        return advance(memory, self, 0xd8, 0);
    case 0x0010d680: {
        const auto start = memory.read_u32(add32(self, 0xd8)); // 10D720 LW.
        const auto length = source_strlen(memory, start); // verified 1FDC64.
        (void)advance(memory, self, 0xd8, sext32(add32(length, 1)));
        return sext32(start); // 10D6B0 restores saved s0 into v0.
    }
    case 0x0010d6c8: return read_be(memory, self, 0xdc, a1);
    case 0x0010d700:
        seek(memory, self, 0xd8, a1);
        return 0; // Host placeholder for unchanged source v0.
    case 0x0010d720: return sext32(memory.read_u32(add32(self, 0xd8)));
    case 0x0010d728:
        memory.write_u32(add32(self, 0xdc), memory.read_u32(add32(self, 0xd8)));
        return 0;
    case 0x0010d738:
        memory.write_u32(add32(self, 0xd0), static_cast<std::uint32_t>(a1));
        return 0;
    case 0x0010d740: return sext32(memory.read_u32(add32(self, 0xd0)));
    case 0x0010d748: return sext32(memory.read_u32(add32(self, 0xd4)));
    case 0x0010d750:
        return sext32(add32(label_record(memory, self,
                                        memory.read_u32(add32(self, 0xd4))), 8));
    case 0x0010d780:
        memory.write_u32(add32(self, 0xd4), static_cast<std::uint32_t>(a1));
        return 0;
    case 0x0010d788: return advance(memory, self, 0xdc, a1);
    case 0x0010d7b0:
        seek(memory, self, 0xdc, a1);
        return 0;
    case 0x0010d7d0:
    case 0x0010d800:
        // Source ADDIU biases selector by 0x20/0x2A before 10D738 + 10D700.
        memory.write_u32(add32(self, 0xd0), add32(static_cast<std::uint32_t>(a1),
                                               entry == 0x0010d7d0 ? 0x20u : 0x2au));
        seek(memory, self, 0xd8, 0);
        return 0;
    case 0x0010d830:
        // 10D844 keeps a1 unchanged for selector; a2 is saved in s1 for offset.
        memory.write_u32(add32(self, 0xd0), static_cast<std::uint32_t>(a1));
        seek(memory, self, 0xd8, a2);
        return 0;
    case 0x0010dae8: return 0; // Original JR delay slot explicitly sets v0=0.
    case 0x0010daf0: {
        const auto offset = memory.read_u32(add32(label_record(memory, self, a2), 4));
        memory.write_u32(add32(self, 0xd0), static_cast<std::uint32_t>(a1));
        seek(memory, self, 0xd8, sext32(offset));
        memory.write_u32(add32(self, 0xd4), static_cast<std::uint32_t>(a2));
        return sext32(offset); // D830/D780 leave FA28's v0 intact.
    }
    case 0x0010db48: {
        const auto name = static_cast<std::uint32_t>(a2);
        const auto offset = memory.read_u32(add32(find_label(memory, self, a1, name), 4));
        memory.write_u32(add32(self, 0xd0), static_cast<std::uint32_t>(a1));
        seek(memory, self, 0xd8, sext32(offset));
        if (memory.read_u8(name) == 0x5f) return sext32(offset);
        // Repeat the lookup after seek, as the original FA88 call does.
        const auto id = memory.read_u16(add32(find_label(memory, self, a1, name), 2));
        memory.write_u32(add32(self, 0xd4), id);
        return id;
    }
    case 0x0010dc30: {
        const auto record = history_record(memory, self, a1);
        if ((memory.read_u32(add32(record, 4)) & 0x01000000u) != 0) return 0;
        return (memory.read_u32(record) & 0x90000000u) == 0x90000000u ? 1 : 0;
    }
    case 0x0010e630: return sext32(history_record(memory, self, a1));
    case 0x0010e640: {
        const auto field = add32(add32(self, static_cast<std::uint32_t>(a2) << 2), 0x13c);
        return sext32(add32(memory.read_u32(field), static_cast<std::uint32_t>(a1) << 3));
    }
    case 0x0010e658: {
        const auto record = history_record(memory, self, a1);
        memory.write_u32(add32(self, 0x174), static_cast<std::uint32_t>(a1));
        memory.write_u32(add32(self, 0x170), 1);
        const auto previous_valid = unpack_history(memory, self, a1,
                                                   sext32(add32(self, 0x178)),
                                                   sext32(add32(self, 0x17c)), true);
        const auto word1 = memory.read_u32(add32(record, 4));
        const auto word0 = memory.read_u32(record);
        memory.write_u32(add32(record, 4), (word1 & 0xfffffc1fu) |
                          ((static_cast<std::uint32_t>(a2) & 0x1fu) << 5));
        memory.write_u32(record, (word0 & 0xf0003fffu) |
                          ((static_cast<std::uint32_t>(a3) & 0x3fffu) << 14));
        return previous_valid;
    }
    case 0x0010e708:
        if (memory.read_u32(add32(self, 0x170)) == 0 ||
            a1 != sext32(memory.read_u32(add32(self, 0x174)))) return 0;
        if (a2 != 0)
            memory.write_u32(static_cast<std::uint32_t>(a2), memory.read_u32(add32(self, 0x178)));
        if (a3 != 0)
            memory.write_u32(static_cast<std::uint32_t>(a3), memory.read_u32(add32(self, 0x17c)));
        return 1;
    case 0x0010e748: return unpack_history(memory, self, a1, a2, a3, true);
    case 0x0010e878: {
        const auto record = history_record(memory, self, a1);
        const auto word1 = memory.read_u32(add32(record, 4));
        const auto word0 = memory.read_u32(record);
        memory.write_u32(add32(record, 4), (word1 & 0xffffffe0u) |
                          (static_cast<std::uint32_t>(a2) & 0x1fu));
        memory.write_u32(record, (word0 & 0xffffc000u) |
                          (static_cast<std::uint32_t>(a3) & 0x3fffu));
        return sext32(record);
    }
    case 0x0010e8d8: return unpack_history(memory, self, a1, a2, a3, false);
    case 0x0010e9d8: return unpack_history(memory, self, a1, 0, 0, false);
    case 0x0010edc0:
        return mark_history(memory, self, memory.read_u32(add32(self, 0xd4)), 0, 0x80000000u);
    case 0x0010edf0:
        return memory.read_u32(history_record(memory, self, a1)) >> 31;
    case 0x0010ee18: {
        const auto name = static_cast<std::uint32_t>(a1);
        const auto selector = find_selector(memory, self, name);
        const auto id = memory.read_u16(add32(find_label(memory, self, sext32(selector), name), 2));
        if (unpack_history(memory, self, id, 0, 0, false) == 0) return 0;
        // E8D8 writes only to its caller's stack temporary here. That stack is
        // replaced by a host local, matching the core's established ABI boundary.
        const auto index = memory.read_u32(history_record(memory, self, id)) & 0x3fffu;
        return sext32(add32(label_record(memory, self, index), 8));
    }
    case 0x0010eea0: return mark_history(memory, self, a1, 0, 0x20000000u);
    case 0x0010eed0:
        return mark_history(memory, self, memory.read_u32(add32(self, 0xd4)), 0, 0x40000000u);
    case 0x0010eee8: return mark_history(memory, self, a1, 0, 0x40000000u);
    case 0x0010ef18:
        return (memory.read_u32(history_record(memory, self, a1)) & 0x40000000u) != 0 ? 1 : 0;
    case 0x0010ef48:
        return mark_history(memory, self, memory.read_u32(add32(self, 0xd4)), 4, 0x01000000u);
    case 0x0010ef60: return mark_history(memory, self, a1, 4, 0x01000000u);
    case 0x0010ef90:
        return (memory.read_u32(add32(history_record(memory, self, a1), 4)) & 0x01000000u) != 0 ? 1 : 0;
    case 0x0010efc0: {
        const auto id = memory.read_u16(add32(find_label(memory, self, a1, static_cast<std::uint32_t>(a2)), 2));
        return (memory.read_u32(add32(history_record(memory, self, id), 4)) & 0x01000000u) != 0 ? 1 : 0;
    }
    case 0x0010eff0:
        return (memory.read_u32(history_record(memory, self, a1)) >> 28) & 1u;
    case 0x0010f018: {
        const auto id = memory.read_u16(add32(find_label(memory, self, a1, static_cast<std::uint32_t>(a2)), 2));
        return (memory.read_u32(history_record(memory, self, id)) >> 28) & 1u;
    }
    case 0x0010f070: {
        const auto index = memory.read_u32(add32(self, 0x148));
        const auto size = memory.read_u32(add32(self, 0x134));
        const auto from = memory.read_u32(add32(self, 0x138));
        memory.write_u32(add32(self, 0x148), index + 1u);
        const auto to = memory.read_u32(add32(add32(self, index << 2), 0x13c));
        (void)source_memcpy(memory, sext32(to), sext32(from), sext32(size << 3));
        return sext32(memory.read_u32(add32(self, 0x148)) - 1u);
    }
    case 0x0010f0c0: {
        const auto index = memory.read_u32(add32(self, 0x148)) - 1u;
        const auto size = memory.read_u32(add32(self, 0x134));
        const auto to = memory.read_u32(add32(self, 0x138));
        memory.write_u32(add32(self, 0x148), index);
        const auto from = memory.read_u32(add32(add32(self, index << 2), 0x13c));
        return source_memcpy(memory, sext32(to), sext32(from), sext32(size << 3));
    }
    case 0x0010f100:
        memory.write_u32(add32(self, 0x148), memory.read_u32(add32(self, 0x148)) - 1u);
        return 0; // Host placeholder for unchanged source v0.
    case 0x0010f628: return label_hash(memory, static_cast<std::uint32_t>(a1));
    case 0x0010f678: {
        const auto count = memory.read_u32(add32(self, 0xc4));
        if (count != 0 && (count & 0x80000000u) == 0) {
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto block = memory.read_u32(add32(add32(self, i << 2), 8));
                for (std::uint32_t bucket = 0; bucket < 256; ++bucket) {
                    const auto field = add32(add32(block, bucket << 2), 0x30);
                    const auto offset = memory.read_u32(field);
                    if (offset != 0) memory.write_u32(field, add32(offset, block));
                }
                const auto base = add32(block, 0x430);
                memory.write_u32(base, add32(memory.read_u32(base), block));
            }
        }
        return 0; // Original leaves v0 untouched.
    }
    case 0x0010f6e0: {
        const auto count = memory.read_u32(add32(self, 0xc4));
        std::uint32_t next_id = 0;
        if (count != 0 && (count & 0x80000000u) == 0) {
            for (std::uint32_t i = 0; i < count; ++i) {
                const auto block = memory.read_u32(add32(add32(self, i << 2), 8));
                for (std::uint32_t bucket = 0; bucket < 256; ++bucket) {
                    auto record = memory.read_u32(add32(add32(block, bucket << 2), 0x30));
                    if (record == 0) continue;
                    for (;;) {
                        if (memory.read_u8(add32(record, 8)) == 0x5f)
                            memory.write_u16(add32(record, 2), 0xffff);
                        else {
                            memory.write_u16(add32(record, 2), static_cast<std::uint16_t>(next_id));
                            ++next_id;
                        }
                        const auto stride = memory.read_u16(record);
                        record = add32(record, stride);
                        if (stride == 0) break;
                    }
                }
            }
        }
        memory.write_u32(add32(self, 0xc8), next_id);
        return 0; // Original leaves v0 untouched.
    }
    case 0x0010f820:
        return sext32(find_label(memory, self, a1, static_cast<std::uint32_t>(a2)));
    case 0x0010f8b0:
        return label_exists(memory, self, a1, static_cast<std::uint32_t>(a2)) ? 1 : 0;
    case 0x0010f938:
        return find_selector(memory, self, static_cast<std::uint32_t>(a1)) != 0xffffffffu ? 1 : 0;
    case 0x0010f9b0:
        return sext32(find_selector(memory, self, static_cast<std::uint32_t>(a1)));
    case 0x0010f898: return sext32(label_record(memory, self, a1));
    case 0x0010fa28: return sext32(memory.read_u32(add32(label_record(memory, self, a1), 4)));
    case 0x0010fa48:
        return sext32(memory.read_u32(add32(find_label(memory, self, a1, static_cast<std::uint32_t>(a2)), 4)));
    case 0x0010fa68: return sext32(add32(label_record(memory, self, a1), 8));
    case 0x0010fa88:
        return memory.read_u16(add32(find_label(memory, self, a1, static_cast<std::uint32_t>(a2)), 2));
    case 0x0010fab8:
        memory.write_u32(add32(self, 0x168), 0);
        return 0;
    case 0x0010fac0: return sext32(memory.read_u32(add32(self, 0x168)));
    case 0x0010fac8:
        memory.write_u32(add32(self, 0x168), static_cast<std::uint32_t>(a1));
        return 0;
    case 0x0010d868:
        throw std::runtime_error("script_data unresolved entry 0010d868: external state/history/resource callbacks");
    default:
        throw std::invalid_argument("script_data entry is outside recovered source scope");
    }
}
}
