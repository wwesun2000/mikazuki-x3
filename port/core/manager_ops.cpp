#include "manager_ops.hpp"
#include "control_transfer.hpp"
#include "guest_memory.hpp"
#include "script_data.hpp"

#include <stdexcept>

namespace kx3 {
namespace {
using u32 = std::uint32_t;
using u64 = std::uint64_t;
constexpr u64 sx(u32 value) noexcept {
    return (value & 0x80000000u) ? 0xffffffff00000000ull | value : value;
}
// 10FB38 and 1204A0. Existing nonzero instances require no writes. A cold path
// invokes source allocation/construction and is deliberately not substituted.
u32 hot_singleton(GuestMemory& memory, u32 gp, bool manager) {
    if (gp == 0) throw std::invalid_argument("manager_ops requires explicit guest gp");
    const auto value = memory.read_u32(gp - (manager ? 0x7cb0u : 0x7bb0u));
    if (value == 0) throw std::runtime_error(manager
        ? "10fb38 cold singleton unresolved: 10fad0 -> allocator; 110628 constructor"
        : "1204a0 cold singleton unresolved: 10fad0 allocator; 120450 constructor");
    return value;
}

// 1134E8 stores state+8 before requesting the next singleton, then saves the
// selector and offset before D800 switches to selector (mode+0x2A). Keep this
// exact order for guest object aliases. The caller owns transactional rollback.
u64 enter_mode(GuestMemory& memory, u32 state, u64 mode, u32 gp) {
    const auto manager = hot_singleton(memory, gp, true);
    const auto script = memory.read_u32(manager + 0x38); // 1133A8, owner dispatch.cpp.
    const auto previous_handler = memory.read_u32(manager + 0x40); // 111560.
    memory.write_u32(state + 8, previous_handler);
    const auto handler = hot_singleton(memory, gp, false); // Original 1204A0 call.
    memory.write_u32(manager + 0x40, handler); // 1114F0.
    const auto selector = invoke_script_data(memory, 0x10d740, script, 0, 0);
    memory.write_u32(state, static_cast<u32>(selector));
    const auto offset = invoke_script_data(memory, 0x10d610, script, 0, 0);
    memory.write_u32(state + 4, static_cast<u32>(offset));
    (void)invoke_script_data(memory, 0x10d800, script, mode, 0);
    return offset; // D800 and its two callees leave D610's v0 intact.
}


}

bool has_manager_op(u32 entry) noexcept {
    switch (entry) {
    case 0x10fb38: case 0x111738: case 0x1133c0:
    case 0x113460: case 0x113468: case 0x113470: case 0x113478:
    case 0x113480: case 0x113488: case 0x113490: case 0x113498:
    case 0x1134a0: case 0x1134a8: case 0x1134b0: case 0x1134b8:
    case 0x1134c0: case 0x1134c8: case 0x1134d0: case 0x1134e8:
    case 0x1137f8: case 0x113808: case 0x114470: case 0x114a50: case 0x114a68:
    case 0x114a78: case 0x115cd8: case 0x119de8: case 0x11a5c8:
    case 0x11a650: case 0x1204a0: case 0x125c40: return true;
    default: return false;
    }
}

u64 invoke_manager_ops(GuestMemory& memory, u32 entry, u32 self,
                        u64 a1, u64 a2, u64 a3, u32 gp) {
    (void)a3;
    switch (entry) {
    case 0x10fb38: return sx(hot_singleton(memory, gp, true));
    case 0x1204a0: return sx(hot_singleton(memory, gp, false));
    case 0x111738: return run_vm_context(memory,entry,self,a1,a2,a3,nullptr);
    case 0x1133c0: return sx(memory.read_u32(self + (static_cast<u32>(a1) << 2) + 0x280));
    case 0x113460: return sx(memory.read_u32(self + 0x3c));
    case 0x113468: return sx(memory.read_u32(self + 0x04));
    case 0x113470: return sx(memory.read_u32(self + 0x08));
    case 0x113478: return sx(memory.read_u32(self + 0x0c));
    case 0x113480: return sx(memory.read_u32(self + 0x10));
    case 0x113488: return sx(memory.read_u32(self + 0x14));
    case 0x113490: return sx(memory.read_u32(self + 0x18));
    case 0x113498: return sx(memory.read_u32(self + 0x1c));
    case 0x1134a0: return sx(memory.read_u32(self + 0x24));
    case 0x1134a8: return sx(memory.read_u32(self + 0x28));
    case 0x1134b0: return sx(memory.read_u32(self + 0x34));
    case 0x1134b8: return sx(memory.read_u32(self + 0x2c));
    case 0x1134c0: return sx(memory.read_u32(self + 0x20));
    case 0x1134c8: return sx(memory.read_u32(self + 0x30));
    case 0x1134d0:
        memory.write_u32(self + 0x0c, 0);
        memory.write_u32(self + 0x08, 1);
        memory.write_u32(self, 0);
        memory.write_u32(self + 0x04, 0);
        return 0;
    case 0x1134e8: return enter_mode(memory, self, a1, gp);
    case 0x125c40: {
        const auto manager = hot_singleton(memory, gp, true);
        const auto index = static_cast<u32>(a1) - 0x0du;
        u64 mode = 0;
        if (sx(index) < 5) {
            // Source data table at 22A8C8 selects the actual original jump arm.
            // Read guest image data; do not silently accept a modified target.
            const auto target = memory.read_u32(0x22a8c8 + (index << 2));
            switch (target) {
            case 0x125c80: mode = 0; break;
            case 0x125ca0: mode = 1; break;
            case 0x125ca8: mode = 4; break;
            case 0x125cb0: mode = 2; break;
            case 0x125cb8: mode = 3; break;
            default: throw std::runtime_error("125c40 unsupported guest mode jump-table target");
            }
        }
        (void)enter_mode(memory, manager + 0x2c4, mode, gp);
        return 0;
    }
    case 0x1137f8:case 0x113808:
        memory.write_u32(self + 4, static_cast<u32>(a1));
        memory.write_u32(self, entry==0x113808); // Delay slots 113800 and 113814.
        return 0;
    case 0x114470:
        for (u32 i = 0; i < 10; ++i) {
            const auto record = self + i * 100;
            if (memory.read_u32(record) != 0) memory.write_u32(record + 12, 1);
        }
        return 0;
    case 0x114a50:
        memory.write_u32(self + 0x3f0, 0);
        memory.write_u32(self + 0x3e8, 1);
        memory.write_u32(self + 0x3ec, 0);
        return 0;
    case 0x114a68:
        memory.write_u32(self + 0x3ec, 1);
        return 0;
    case 0x114a78: {
        const auto old = memory.read_u32(self + 0x3f0);
        memory.write_u32(self + 0x3e8, old == 0 ? 1 : 0);
        memory.write_u32(self + 0x3f0, old + 1u);
        return 0;
    }
    case 0x115cd8:
        memory.write_u32(self + 0x10, memory.read_u32(self + 0x0c));
        return 0;
    case 0x119de8: return memory.read_u32(self + 4) != 0 ? 1 : 0;
    case 0x11a650: return sx(memory.read_u32(self));
    case 0x11a5c8: {
        const auto manager = hot_singleton(memory, gp, true);
        const auto script = memory.read_u32(manager + 0x38); // 1133A8 result retained in v0.
        (void)invoke_script_data(memory, 0x10d738, script, sx(memory.read_u32(self + 4)), 0);
        (void)invoke_script_data(memory, 0x10d780, script, sx(memory.read_u32(self + 8)), 0);
        const auto offset = sx(memory.read_u32(self + 12));
        const auto selector = sx(memory.read_u32(self + 4));
        (void)invoke_script_data(memory, 0x10d830, script, selector, offset);
        memory.write_u32(manager + 0x40, memory.read_u32(self + 16)); // 1114F0.
        memory.write_u32(self, 0);
        return sx(script);
    }
    default:
        throw std::invalid_argument("manager_ops entry outside recovered source scope");
    }
}
}
