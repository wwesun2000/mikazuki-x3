#include "choice.hpp"
#include "guest_memory.hpp"

#include <stdexcept>
#include <sstream>

namespace kx3 {
namespace {
// R5900 LW and ADDIU sign-extend their low 32-bit result to the 64-bit GPR.
std::uint64_t sx32(std::uint32_t value) {
    return (value & 0x80000000u) ? (0xffffffff00000000ull | value) : value;
}
std::int64_t signed32(std::uint32_t value) {
    return value & 0x80000000u ? std::int64_t(value) - 0x100000000ll : value;
}
}

// Source ELF SHA-256:
// 50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160.
// Exact machine instructions are retained in choice-runtime-v1 and its oracle.
std::uint64_t invoke_choice_leaf(GuestMemory& memory, std::uint32_t entry,
                                std::uint32_t self, std::uint64_t a1) {
    switch (entry) {
    case 0x00117d00: // JR RA; delay-slot SW A1, 0xC(A0).
        memory.write_u32(self + 0xcu, std::uint32_t(a1));
        return 0;
    case 0x00117d08:
        return sx32(memory.read_u32(self + 0x78u));
    case 0x00117d10: { // Preview iterator reached count - 1; not focus.
        const auto count_minus_one = memory.read_u32(self + 4u) - 1u;
        const auto preview_index = memory.read_u32(self + 8u);
        return signed32(preview_index) >= signed32(count_minus_one);
    }
    case 0x00117d28:
    case 0x00117d40: {
        const std::uint32_t scaled = memory.read_u32(self + 0x168u) << 2;
        const std::uint32_t field = entry == 0x00117d28 ? 0x1cu : 0x44u;
        return sx32(memory.read_u32(self + scaled + field));
    }
    case 0x00117d58:
        return sx32(memory.read_u32(self + 0xcu));
    case 0x00117e08:
        return memory.read_u32(self + 0x168u) == 0;
    case 0x00117e18:
        return memory.read_u32(self + 0x168u) == memory.read_u32(self + 4u) - 1u;
    case 0x00118e20:
        return sx32(memory.read_u32(self + 0x1c4u));
    case 0x00118e28:
        return sx32(memory.read_u32(self + 0x194u));
    case 0x00118e30:
        return sx32(memory.read_u32(self + 0x190u));
    case 0x0011e828: // Interactive context slot 1 blocks script dispatch.
        return 1;
    default:
        std::ostringstream message;
        message<<"Unrecovered choice entry 0x"<<std::hex<<entry;
        throw std::runtime_error(message.str());
    }
}
}
