#pragma once
#include "guest_memory.hpp"
#include "recovered.hpp"

namespace kx3 {
// Native host boundary around one original context method. Failure rolls back
// guest fields/cursor; it never skips an unrecovered opcode and continues.
inline std::uint64_t step_context_atomic(GuestMemory& memory, std::uint32_t manager,
                                        ExecutionServices* services = nullptr) {
    GuestMemory::AccessBudget budget(memory,8'000'000);
    GuestMemory::Transaction transaction(memory);
    const auto context = memory.read_u32(manager + 0x40);
    const auto step = memory.read_u32(memory.read_u32(context) + 4);
    const auto result = invoke_recovered(memory, step, context, manager, 0, 0, services);
    transaction.commit();
    return result;
}

// Original113148 inner-loop selection. Text mode must route to1126E0; treating
// text bytes as ordinary context opcodes would silently consume story content.
// Main-tick input gates, presentation progression and profiler calls remain a
// separate layer and are not claimed by this one-instruction host boundary.
inline std::uint64_t step_script_atomic(GuestMemory& memory,std::uint32_t manager,
                                      ExecutionServices* services=nullptr) {
    GuestMemory::AccessBudget budget(memory,8'000'000);
    GuestMemory::Transaction transaction(memory);
    std::uint64_t result;
    if(memory.read_u32(manager+0x2b4))
        result=invoke_recovered(memory,0x001126e0,manager,0,0,0,services);
    else {
        const auto context=memory.read_u32(manager+0x40);
        const auto step=memory.read_u32(memory.read_u32(context)+4);
        result=invoke_recovered(memory,step,context,manager,0,0,services);
    }
    transaction.commit();
    return result;
}
}
