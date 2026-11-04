#include "control_transfer.hpp"
#include <stdexcept>

namespace kx3 {
namespace {
using u32=std::uint32_t; using u64=std::uint64_t;
}
bool has_control_transfer(u32 entry) noexcept {
    switch(entry){
#define KX3_MENU_ENTRY(address,fn) case address:
#include "scenario_branches_entries.hpp"
#undef KX3_MENU_ENTRY
    case 0x133f60:case 0x10d260:case 0x122070:case 0x1218f8:
    case 0x10c8f8:case 0x122090:case 0x1220d0:case 0x122118:
    return true;
    default:return false;
    }
}
u64 invoke_control_transfer(GuestMemory& m,u32 entry,u32 self,u64 a1,u64 a2,u64 a3,ExecutionServices* services) {
    switch(entry) {
    // The menu return can enter 11DEF8. At 11DF7C the script lookup
    // receives two pointers into its caller's EE stack as output parameters.
    case 0x10c8f8:return run_vm_context(m,entry,self,a1,a2,a3,services);
    case 0x133f60:case 0x10d260:case 0x122070:case 0x1218f8:
    case 0x122090:case 0x1220d0:case 0x122118:
        return run_scenario_return(m,entry,self,a1,services);
#define KX3_MENU_ENTRY(address,fn) case address:
#include "scenario_branches_entries.hpp"
#undef KX3_MENU_ENTRY
        return run_vm_context(m,entry,self,a1,a2,a3,services);
    default:throw std::runtime_error("Unrecovered control-transfer entry");
    }
}
}
