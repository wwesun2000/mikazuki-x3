#include "ps2recomp_pilot_runtime.hpp"
#include <ps2_recompiled_functions.h>

#include <algorithm>
#include <bit>
#include <charconv>
#include <iostream>
#include <span>
#include <sstream>
#include <string_view>
#include <vector>

namespace {
using namespace ee_pilot;

std::uint32_t number(std::string_view text, int radix) {
    std::uint32_t value = 0;
    auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, radix);
    if (error != std::errc{} || end != text.data() + text.size() || (radix == 16 && text.size() != 8))
        throw std::runtime_error("Expected eight hex digits for a float, or a decimal frame count");
    return value;
}

std::string hex32(std::uint32_t value) {
    std::ostringstream out;
    out << std::hex << std::setfill('0') << std::setw(8) << value;
    return out.str();
}

std::string hexbytes(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(2 * bytes.size());
    for (auto byte : bytes) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 15]);
    }
    return out;
}

void run(std::uint32_t height, std::uint32_t step, std::uint32_t frames) {
    if (!frames || frames > 100000) throw std::runtime_error("Frame count must be between 1 and 100000");
    static_assert(sizeof(void*) == 8 && std::endian::native == std::endian::little);
    static_assert(alignof(R5900Context) >= 16 && sizeof(R5900Context::r[0]) == 16);
    std::vector<std::uint8_t> ram(PS2_RAM_SIZE);
    const auto memory = std::span(ram);
    std::fill_n(ram.begin() + task, 64, 0xa5);
    std::fill_n(ram.begin() + data, 16, 0x7c);
    std::fill_n(ram.begin() + stack - 16, 32, 0x6d);
    Ps2FastWrite32(ram.data(), task + 0x2c, data);
    Ps2FastWrite32(ram.data(), data + 4, height);
    Ps2FastWrite32(ram.data(), data + 8, step);
    R5900Context cpu;
    auto ctx = &cpu;
    SET_GPR_U32(ctx, 4, task);
    SET_GPR_U32(ctx, 5, 0x127);
    SET_GPR_U32(ctx, 29, stack);
    SET_GPR_U32(ctx, 31, return_pc);
    for (std::uint32_t frame = 1; frame <= frames; ++frame) {
        auto before = Ps2FastRead32(ram.data(), data + 4);
        cpu.pc = 0x184760;
        // This closure has exactly one direct tail jump to a second real
        // generated function. Additional runtime services cannot link here.
        FUN_00184760_0x184760(ram.data(), ctx, nullptr);
        if (cpu.pc != return_pc || cpu.in_delay_slot)
            throw std::runtime_error("Generated callback did not return to its caller");
        std::cout << "{\"frame\":" << frame << ",\"height\":\"" << hex32(before)
                  << "\",\"step\":\"" << hex32(step)
                  << "\",\"height_after\":\"" << hex32(Ps2FastRead32(ram.data(), data + 4))
                  << "\",\"done_word\":\"" << hex32(Ps2FastRead32(ram.data(), task + 16))
                  << "\",\"pc\":\"" << hex32(cpu.pc)
                  << "\",\"a0\":\"" << hex32(GPR_U32(ctx, 4)) << "\",\"a1\":\"" << hex32(GPR_U32(ctx, 5))
                  << "\",\"sp\":\"" << hex32(GPR_U32(ctx, 29)) << "\",\"ra\":\"" << hex32(GPR_U32(ctx, 31))
                  << "\",\"t7\":\"" << hex32(GPR_U32(ctx, 15))
                  << "\",\"f0\":\"" << hex32(std::bit_cast<std::uint32_t>(cpu.f[0]))
                  << "\",\"f1\":\"" << hex32(std::bit_cast<std::uint32_t>(cpu.f[1]))
                  << "\",\"f2\":\"" << hex32(std::bit_cast<std::uint32_t>(cpu.f[2]))
                  << "\",\"task\":\"" << hexbytes(memory.subspan(task, 64)) << "\",\"data\":\"" << hexbytes(memory.subspan(data, 16))
                  << "\",\"stack\":\"" << hexbytes(memory.subspan(stack - 16, 32)) << "\"}\n";
    }
}
}

int main(int argc, char** argv) {
    try {
        if (argc != 5 || std::string_view(argv[1]) != "expandband")
            throw std::runtime_error("Usage: pilot_host expandband HEIGHT_HEX STEP_HEX FRAMES");
        run(number(argv[2], 16), number(argv[3], 16), number(argv[4], 10));
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
