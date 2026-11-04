#include "source_libc.hpp"
#include "guest_memory.hpp"

#include <algorithm>
#include <array>
#include <span>

namespace kx3 {
namespace {
// Evidence: analysis/ghidra/vm-dependencies-v1/functions/{001fdb50,001fda0c,
// 001fc524}.json and reader-dependencies-v1/functions/001fdc64.json.
// LQ/MMI string paths retain their 16-byte reads, but their arithmetic zero
// detection is expressed over bytes. Do not mistake static recovery for an
// executed MMI oracle: the current Ghidra language lacks its CALLOTHER handlers.
constexpr std::uint64_t sext32(std::uint32_t bits) noexcept {
    return (bits & 0x80000000u) ? (0xffffffff00000000ull | bits) : bits;
}

std::array<std::uint8_t, 16> read_block(GuestMemory& memory, std::uint32_t address,
                                      std::uint32_t width) {
    std::array<std::uint8_t, 16> copy{};
    const auto source = memory.bytes(address, width);
    std::copy(source.begin(), source.end(), copy.begin());
    return copy;
}

bool contains_zero(const std::array<std::uint8_t, 16>& block, std::uint32_t width) {
    for (std::uint32_t i = 0; i < width; ++i)
        if (block[i] == 0) return true;
    return false;
}

void transfer(GuestMemory& memory, std::uint32_t destination,
              std::uint32_t source, std::uint32_t width) {
    const auto loaded = read_block(memory, source, width);
    memory.write_bytes(destination, std::span<const std::uint8_t>(loaded.data(), width));
}
}

std::uint32_t source_strlen(GuestMemory& memory, std::uint32_t start) {
    auto cursor = start;
    const std::uint32_t width = (start & 7u) != 0 ? 0u : ((start & 15u) == 0 ? 16u : 8u);
    if (width != 0) {
        while (!contains_zero(read_block(memory, cursor, width), width)) cursor += width;
    }
    while (memory.read_u8(cursor) != 0) ++cursor;
    return cursor - start;
}

std::uint64_t source_strcpy(GuestMemory& memory, std::uint64_t destination,
                            std::uint64_t source) {
    auto from = static_cast<std::uint32_t>(source);
    auto to = static_cast<std::uint32_t>(destination);
    const auto alignment = from | to;
    if ((alignment & 7u) == 0) {
        const auto width = (alignment & 15u) == 0 ? 16u : 8u;
        for (;;) {
            const auto block = read_block(memory, from, width);
            if (contains_zero(block, width)) break;
            memory.write_bytes(to, std::span<const std::uint8_t>(block.data(), width));
            from += width;
            to += width;
        }
    }
    for (;;) {
        const auto byte = memory.read_u8(from);
        ++from;
        memory.write_u8(to, byte);
        ++to;
        if (byte == 0) return destination; // 1FDC60 MOVE v0,a3, not inferred void.
    }
}

std::uint64_t source_strcmp(GuestMemory& memory, std::uint64_t left,
                            std::uint64_t right) {
    auto a = static_cast<std::uint32_t>(left);
    auto b = static_cast<std::uint32_t>(right);
    const auto alignment = a | b;
    if ((alignment & 7u) == 0) {
        // 1FDA54 delay slot reads right LD even on the following LQ path.
        auto right_block = read_block(memory, b, 8);
        const auto width = (alignment & 15u) == 0 ? 16u : 8u;
        auto left_block = read_block(memory, a, width);
        if (width == 16) right_block = read_block(memory, b, 16);
        bool first_equal = true;
        for (;;) {
            if (!std::equal(left_block.begin(), left_block.begin() + width, right_block.begin())) break;
            // Source reloads left on the first equal comparison. Normal RAM has
            // no read side effects; retain its access boundary without MMIO.
            if (first_equal) left_block = read_block(memory, a, width);
            first_equal = false;
            if (contains_zero(left_block, width)) return 0;
            a += width;
            b += width;
            left_block = read_block(memory, a, width);
            right_block = read_block(memory, b, width);
        }
    }
    for (;;) {
        const auto first = memory.read_u8(a);
        if (first == 0)
            return sext32(std::uint32_t{0} - memory.read_u8(b));
        const auto second = memory.read_u8(b);
        if (first != second)
            return sext32(static_cast<std::uint32_t>(first) - second);
        ++a;
        ++b;
    }
}

std::uint64_t source_memcpy(GuestMemory& memory, std::uint64_t destination,
                            std::uint64_t source, std::uint64_t count) {
    auto from = static_cast<std::uint32_t>(source);
    auto to = static_cast<std::uint32_t>(destination);
    // Initial SLTIU uses all 64 input bits. Subsequent ADDIU sign-extends its
    // wrapped low 32 bits, as in the original; callers normally pass SLL sizes.
    if (count >= 32 && ((from | to) & 15u) == 0) {
        do {
            const auto first = read_block(memory, from, 16);
            count = sext32(static_cast<std::uint32_t>(count) - 32u);
            from += 16;
            memory.write_bytes(to, std::span<const std::uint8_t>(first.data(), 16));
            to += 16;
            transfer(memory, to, from, 16); // Read AFTER the first store: overlap matters.
            from += 16;
            to += 16;
        } while (count >= 32);
        while (count >= 8) {
            transfer(memory, to, from, 8);
            count = sext32(static_cast<std::uint32_t>(count) - 8u);
            from += 8;
            to += 8;
        }
    }
    count = sext32(static_cast<std::uint32_t>(count) - 1u);
    while (count != 0xffffffffffffffffull) {
        const auto byte = memory.read_u8(from);
        count = sext32(static_cast<std::uint32_t>(count) - 1u);
        ++from;
        memory.write_u8(to, byte);
        ++to;
    }
    return destination;
}
}
