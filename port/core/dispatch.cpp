#include "dispatch.hpp"
#include "guest_memory.hpp"
#include "recovered.hpp"
#include <stdexcept>

namespace kx3 {
namespace {
using u32 = std::uint32_t;
using u64 = std::uint64_t;
u64 lw(GuestMemory& m, u32 address) {
    return static_cast<u64>(static_cast<std::int64_t>(static_cast<std::int32_t>(m.read_u32(address))));
}
}

u64 invoke_dispatch(GuestMemory& m, u32 entry, u32 self, u64 a1, u64 a2, u64 a3, ExecutionServices* services) {
    switch (entry) {
    case 0x001133a8: return lw(m, self + 0x38);
    case 0x001133b0: return lw(m, self + 0x5c + u32(a1) * 4);
    case 0x001114f0:
        m.write_u32(self + 0x40, u32(a1));
        return 0; // Source void; v0 is not defined by this entry.
    case 0x00111560: return lw(m, self + 0x40);
    case 0x00132478: { // Slot 0x40 for opcode 1B returns from the injected text template.
        const auto manager=u32(invoke_recovered(m,0x10fb38,0));
        (void)invoke_dispatch(m,0x113578,manager+0x2c4,0,0,0,services);
        return 0;
    }
    case 0x00113578: {
        const auto manager=u32(invoke_recovered(m,0x10fb38,0));
        (void)invoke_recovered(m,0x10d830,m.read_u32(manager+0x38),lw(m,self),lw(m,self+4),0,services);
        return invoke_dispatch(m,0x1114f0,manager,lw(m,self+8),0,0,services);
    }
    case 0x00120300: return 0;
    case 0x00120250:
        m.write_u32(self, 0x002239f0);
        return 0; // Source void, non-deleting context destructor.
    case 0x00120308: case 0x00120528: {
        const u32 manager = u32(a1);
        const u32 script = u32(invoke_recovered(m, 0x001133a8, manager));
        const u64 offset = invoke_recovered(m, 0x0010d610, script, 0);
        const u32 opcode = u32(invoke_recovered(m, 0x0010d5d8, script, 1));
        const bool special=entry==0x120528;
        const u32 table=special?0x235f48:0x206010;
        for (u32 i = 0; i < (special?2u:113u); ++i) {
            if (m.read_u32(table + i * 4) != opcode) continue;
            const u64 handler = invoke_recovered(m, 0x001133b0, manager, opcode);
            const u32 method = m.read_u32(m.read_u32(self) + 8);
            return invoke_recovered(m, method, self, handler, offset, opcode, services);
        }
        // 120528 explicitly dispatches unlisted opcodes to the source token
        // skipper. The default 120308 context instead consumes just this byte.
        return special?invoke_recovered(m,0x111738,manager,offset,opcode,0,services):0;
    }
    case 0x0011ec30:
    case 0x001203e0:
    case 0x00120410: case 0x00120628: {
        const u32 handler = u32(a1);
        const u32 slot_offset = entry == 0x0011ec30 ? 0x0c : entry == 0x001203e0 ? 0x3c : 0x40;
        const u32 method = m.read_u32(m.read_u32(handler) + slot_offset);
        // Original jalr swaps a0/a1 and leaves a2/a3 intact. The automatically
        // inferred Ghidra prototype omits the latter two; assembly is authority.
        return invoke_recovered(m, method, handler, self, a2, a3, services);
    }
    default: throw std::runtime_error("Unrecovered default-context entry");
    }
}
}
