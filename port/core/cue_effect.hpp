#pragma once
#include <cstdint>

namespace kx3 {
class GuestMemory;
struct ExecutionServices;
std::uint32_t reserve_mode_zero_task(GuestMemory&); // 179B58(0), before allocating the effect-specific payload.
std::uint32_t large_effect_payload(const GuestMemory&,std::uint32_t task,std::uint32_t bytes);
void update_flash_effect(GuestMemory&,std::uint32_t task); // Original 17E288.
bool retained_cue_effect(GuestMemory&,std::uint32_t owner,std::uint32_t blob); // 10C780
void cue_effect_on(GuestMemory&,std::uint32_t owner,std::uint32_t blob,std::uint32_t bytes,ExecutionServices*);
void cue_effect_off(GuestMemory&,std::uint32_t owner,std::uint32_t blob,std::uint32_t bytes);
void cue_effect_change(GuestMemory&,std::uint32_t owner,std::uint32_t blob,std::uint32_t bytes);
bool cue_effect_busy(GuestMemory&,std::uint32_t owner,std::uint32_t id);
void clear_cue_effects(GuestMemory&,std::uint32_t owner);
void tick_cue_effects(GuestMemory&,std::uint32_t heap,ExecutionServices*);
}
