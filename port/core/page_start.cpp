#include "page_start.hpp"
#include "control_transfer.hpp"
#include "guest_memory.hpp"
#include "text_commands.hpp"
#include <bit>

namespace kx3 {
namespace {
using u32 = std::uint32_t;
using u64 = std::uint64_t;

u32 manager(GuestMemory& m) { return u32(invoke_recovered(m, 0x10fb38, 0)); }

// 138F08 tests only pending ring records whose +12 word is zero. Index wraps
// modulo eight. Empty queue and a queue of nonblocking commands are distinct
// representations with the same answer.
bool queued_blocking_command(GuestMemory& m) {
    constexpr u32 loader=0x206250;
    const auto end=m.read_u32(loader+2940);
    auto i=m.read_u32(loader+2944);
    if (i>=8 || end>=8) throw std::runtime_error("Invalid source ring at 0x00138F08");
    while (i!=end) {
        if (m.read_u32(loader+2956+52*i)==0) return true;
        i=(i+1)%8;
    }
    return false;
}

// The caller at 138FF4 consumes only bits 0 and 1 of 135770. The movie
// player's optional query 1959F0 only contributes bit 5. The Windows session
// is serialized; an actual live, separately-owned movie worker is an explicit
// dependency before its semaphore can be acquired.
u32 movie_wait_bits(GuestMemory& m) {
    constexpr u32 loader=0x206250, gp=0x23daf0;
    if (!m.read_u32(0x206810)) return 0; // 137308
    u32 bits=m.read_u32(gp-30852)?1u:0u; // 13F040
    if (!m.read_u32(gp-30864) && m.read_u32(gp-30856)) bits|=2;
    const auto player=m.read_u32(gp-23672);
    if (player && (m.read_u32(player+1088+4)!=0xffffffffu || m.read_u32(player+1088+12)))
        throw std::runtime_error("Movie player semaphore unavailable at 0x00195A28");
    auto f=[&](u32 at){return std::bit_cast<float>(m.read_u32(at));};
    if (f(loader+588)==f(0x235fc8) && f(loader+296)!=0.0f && m.read_u32(loader+104) &&
        !m.read_u32(loader+584) && !m.read_u32(loader+92) &&
        f(loader+288)<f(loader+296)-f(0x235fcc)) bits|=2;
    return bits;
}

bool scene_idle(GuestMemory& m) { // 138FB0, original query order
    constexpr u32 gp=0x23daf0;
    bool ready=!m.read_u32(gp-21452);
    if (queued_blocking_command(m)) ready=false;
    // 138EB8 holds 207140 only while sampling these two indices.
    if (!m.read_u32(0x207140) || m.read_u32(0x207144)!=0xffffffffu || m.read_u32(0x20714c))
        throw std::runtime_error("Cue semaphore unavailable at 0x00138EB8");
    if (m.read_u32(gp-21460)!=m.read_u32(gp-21456)) ready=false;
    if (m.read_u32(0x206dd4) || m.read_u32(gp-21440)) ready=false; // 139078 / 13F740
    if (!m.read_u32(0x2062ac) && movie_wait_bits(m)) ready=false;
    return ready;
}


}

bool has_page_start(u32 entry) noexcept {
    switch (entry) {
    case 0x12f8d8: case 0x12f308: case 0x12f3c0: case 0x12c428: case 0x1050b8: case 0x127f48:
    case 0x12f598: case 0x12f6c0: case 0x12f1a8: case 0x12f6e8: case 0x12f2c8:
        return true;
    default: return false;
    }
}

u64 invoke_page_start(GuestMemory& m, u32 entry, u32 self, u64 a1, ExecutionServices* services) {
    const auto owner = manager(m);
    auto call = [&](u32 addr, u32 object, u64 arg = 0) {
        return invoke_recovered(m, addr, object, arg, 0, 0, services);
    };
    switch (entry) {
    case 0x127f48:
        if (scene_idle(m)) return 0;
        (void)call(0x10d700,m.read_u32(owner+0x38),a1);
        return 1;
    case 0x12c428:case 0x12f3c0:case 0x1050b8:case 0x12f308:case 0x12f598:
    case 0x12f6c0:case 0x12f1a8:case 0x12f6e8:case 0x12f2c8:case 0x12f8d8:
        return run_vm_context(m,entry,self,a1,0,0,services);
    default: throw std::invalid_argument("Unknown page start entry");
    }
}
}
