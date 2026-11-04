#include "text_driver.hpp"
#include "control_transfer.hpp"
#include "session_clock.hpp"
#include "guest_memory.hpp"
#include "manager_ops.hpp"
#include "recovered.hpp"
#include <algorithm>
#include <bit>
#include <cmath>
#include <stdexcept>

namespace kx3 {
namespace {
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i32 = std::int32_t;
constexpr u32 gp = 0x23daf0;
constexpr u32 font_descriptor_cell = gp - 27584;
constexpr u32 rng_state = 0x1e497e8;
constexpr u32 rng_index = gp - 26736;

i32 signed_word(u32 value) { return std::bit_cast<i32>(value); }
u64 extended_word(u32 value) { return u64(std::int64_t(signed_word(value))); }
u64 manager_call(GuestMemory& memory, u32 entry, u32 self, u64 a1 = 0, u64 a2 = 0) {
    return invoke_manager_ops(memory, entry, self, a1, a2, 0, gp);
}
// 17A698/17A6E8. The original lock/unlock remains a required native platform
// binding. Its guest lock fields, caller identity and semaphore are observable.
u32 random_word(GuestMemory& memory, ExecutionServices* services) {
    constexpr u32 mutex = 0x20c7d0;
    (void)invoke_recovered(memory, 0x1536a8, mutex, 0, 0, 0, services);
    auto index = memory.read_u32(rng_index);
    if (signed_word(index) < 0 || index > 625)
        throw std::runtime_error("17A6E8 invalid RNG index");
    if (index >= 624) {
        if (index == 625) {
            u32 seed = 4357;
            for (unsigned i = 0; i < 624; ++i) {
                memory.write_u32(rng_state + 4*i, seed);
                seed *= 69069;
            }
            memory.write_u32(rng_index, 624);
        }
        for (unsigned i = 0; i < 624; ++i) {
            const u32 combined = (memory.read_u32(rng_state + 4*i) & 0x80000000u) |
                (memory.read_u32(rng_state + 4*((i+1)%624)) & 0x7fffffffu);
            const u32 replacement = memory.read_u32(rng_state + 4*((i+397)%624)) ^
                (combined >> 1) ^ memory.read_u32(gp - 26728 + 4*(combined&1));
            memory.write_u32(rng_state + 4*i, replacement);
        }
        index = 0;
    }
    u32 value = memory.read_u32(rng_state + 4*index);
    memory.write_u32(rng_index, index+1);
    value ^= value >> 11;
    value ^= (value << 7) & 0x9d2c5680u;
    value ^= (value << 15) & 0xefc60000u;
    value ^= value >> 18;
    (void)invoke_recovered(memory, 0x153a70, mutex, 0, 0, 0, services);
    return value;
}

float random_fraction(GuestMemory& memory, ExecutionServices* services) {
    const u32 word = random_word(memory, services);
    const float integer = (word & 0x80000000u) ?
        static_cast<float>((word>>1)|(word&1))*2.0f : static_cast<float>(word);
    return integer * std::bit_cast<float>(memory.read_u32(0x237290));
}

i32 draw_integer(GuestMemory& memory, i32 low, i32 high, ExecutionServices* services) {
    const float sample = random_fraction(memory,services);
    const float first = static_cast<float>(low);
    const float end = static_cast<float>(signed_word(u32(high)+1));
    const float scaled = sample*(end-first)+first;
    const float bounded=std::clamp(scaled, first, end);
    if (!std::isfinite(bounded) || bounded>=2147483648.0f || bounded< -2147483648.0f)
        throw std::runtime_error("17AA28 unsupported out-of-range COP1 integer conversion");
    const auto selected = static_cast<i32>(bounded);
    return std::clamp(selected, low, high);
}

u32 find_font_group(const GuestMemory& memory, u32 style, u32 size) {
    const u32 descriptor = memory.read_u32(font_descriptor_cell);
    u32 group = descriptor + 28;
    const i32 count = signed_word(memory.read_u32(descriptor+24));
    for (i32 index = 0; index < count; ++index) {
        if (memory.read_u32(group)==style && memory.read_u32(group+4)==size) return group;
        group = descriptor + memory.read_u32(group+16);
    }
    return 0;
}

u16 transform_unit(GuestMemory& memory, u32 hint, u16 unit, bool ruby, ExecutionServices* services) {
    const u32 manager = u32(manager_call(memory,0x10fb38,0));
    const u32 font = memory.read_u32(manager+0x3c);
    if (!memory.read_u32(hint+4) || !memory.read_u32(hint+8)) return unit;
    const float old = std::bit_cast<float>(memory.read_u32(hint+0x28));
    const float cap = std::bit_cast<float>(memory.read_u32(0x235ec8));
    const float next = old + std::bit_cast<float>(memory.read_u32(0x235ecc));
    memory.write_u32(hint+0x28, std::bit_cast<u32>(next>cap ? cap : next));
    if (old < static_cast<float>(draw_integer(memory,1,100,services))) return unit;
    const u32 format = memory.read_u32(font + (ruby ? 4 : 0));
    const u32 group = find_font_group(memory, memory.read_u32(format+16), memory.read_u32(format+12));
    u16 replacement = 0x8140;
    if (group) {
        const auto count = signed_word(memory.read_u32(group+12));
        if (count<=0) throw std::runtime_error("16BDE0 unsupported empty font group");
        const auto index = draw_integer(memory,0,count-1,services);
        replacement = u16(memory.read_u32(group+20+12*u32(index)));
    }
    if (!ruby) memory.write_u32(hint+0x24,memory.read_u32(hint+0x24)+1);
    return replacement;
}

}

std::uint32_t source_random_word(GuestMemory& memory,ExecutionServices* services){
    return random_word(memory,services);
}
float source_random_range(GuestMemory& memory,float low,float high,ExecutionServices* services) {
    const auto sample=random_fraction(memory,services)*(high-low)+low;
    if(!(low<=sample))return low;
    return high<sample?high:sample; // 17A9C8 tests low first, including reversed bounds.
}
void initialize_clock_and_pad(GuestMemory& memory,u32 counter) {
    // 1107B8..C8 seeds from the low 32 bits of the platform timer (16D1F8).
    // 17A610 -> 17A698, and 15E180 -> 153508 for the second pad lock.
    constexpr u32 rng=0x20c7d0,pad=0x207c58;
    if(memory.read_u32(rng)==UINT32_MAX){
        memory.write_u32(rng,6);memory.write_u32(rng+4,UINT32_MAX);
        memory.write_u32(rng+8,0);memory.write_u32(rng+12,1);
        for(u32 i=0;i<624;++i){memory.write_u32(rng_state+4*i,counter);counter*=69069u;}
        memory.write_u32(rng_index,624);memory.write_u32(gp-21032,0);
    }
    if(memory.read_u32(pad)==UINT32_MAX){
        memory.write_u32(pad,7);memory.write_u32(pad+4,UINT32_MAX);
        memory.write_u32(pad+8,0);memory.write_u32(pad+12,15);
    }
}

bool has_text_driver(u32 entry) noexcept {return entry==0x17aa28 || entry==0x1126e0 || entry==0x119f80 || entry==0x16be70 || entry==0x16b910 || entry==0x1326e0;}
u64 invoke_text_driver(GuestMemory& memory,u32 entry,u32 self,u64 a1,u64 a2,u64,
                       ExecutionServices* services,TextPresentationBackend* backend) {
    switch(entry) {
    case 0x17aa28:return extended_word(u32(draw_integer(memory,signed_word(self),signed_word(u32(a1)),services)));
    case 0x1326e0:return run_vm_context(memory,entry,self,a1,a2,0,services);
    case 0x16be70:
        if(self>0xffff || a1!=extended_word(u32(a1)) || a2!=extended_word(u32(a2)))
            throw std::runtime_error("16BE70 requires original character and font field widths");
        return run_vm_context(memory,entry,self,a1,a2,0,services);
    case 0x16b910:
        if(a1>0xffff)throw std::runtime_error("16B910 requires original two-byte source unit");
        return run_vm_context(memory,entry,self,a1,a2,0,services);
    case 0x119f80:return transform_unit(memory,self,u16(a1),a2!=0,services);
    case 0x1126e0:{
        ExecutionServices local=services?*services:ExecutionServices{};
        local.text=backend;
        return run_vm_context(memory,entry,self,0,0,0,&local);
    }
    default:throw std::invalid_argument("Unrecovered text-driver source entry");
    }
}
}
