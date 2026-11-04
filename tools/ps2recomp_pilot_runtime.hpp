#pragma once

// Keep the real upstream CPU context, register, FPU, branch and fast-RAM
// helpers. This pilot has no device backend. Unused CPU kernels, syscalls
// or unresolved guest function implementations are deliberately not linked.
#include <iomanip>
#include <stdexcept>
#include <ps2_runtime_macros.h>

namespace ee_pilot {
constexpr std::uint32_t task = 0x400000;
constexpr std::uint32_t data = 0x400080;
constexpr std::uint32_t stack = 0x500000;
constexpr std::uint32_t return_pc = 0x3ff000;

inline bool contains(std::uint32_t begin, std::uint32_t length,
                     std::uint32_t address, std::uint32_t width) {
    return width <= length && address >= begin && address - begin <= length - width;
}

inline std::uint32_t checked_ram(std::uint32_t address, std::uint32_t width) {
    if (!contains(0, PS2_RAM_SIZE, address, width) || Ps2IsSpecialAddress(address) ||
        !(contains(task, 64, address, width) || contains(data, 16, address, width) ||
          contains(stack - 16, 32, address, width)))
        throw std::runtime_error("Generated code accessed undeclared guest address " + std::to_string(address));
    return address;
}
}

// Restrict these CPU load/store instructions to the declared original RAM
// ranges, then perform the access with PS2Recomp's own little-endian helpers.
// Other access widths are intentionally not provided by this host.
#undef READ32
#undef READ64
#undef WRITE32
#undef WRITE64
#define READ32(addr) Ps2FastRead32(rdram, ee_pilot::checked_ram(addr, 4))
#define READ64(addr) Ps2FastRead64(rdram, ee_pilot::checked_ram(addr, 8))
#define WRITE32(addr, val) Ps2FastWrite32(rdram, ee_pilot::checked_ram(addr, 4), (val))
#define WRITE64(addr, val) Ps2FastWrite64(rdram, ee_pilot::checked_ram(addr, 8), (val))
