#pragma once
#include "field_feedback.hpp"
#include "screen_wind.hpp"
namespace kx3 {
// Separate from every mode-two wind/wipe slot and the font descriptor at1500000.
inline constexpr std::uint32_t letter_blur_work_begin=0x14f9000,letter_blur_work_stride=64;
static_assert(letter_blur_work_begin>=wind_work_end);
static_assert(letter_blur_work_begin+10*letter_blur_work_stride<=0x1500000);
inline std::uint32_t letter_blur_payload(unsigned slot){
    if(slot>=10)throw std::runtime_error("Letter-blur task slot outside original mode-three pool");
    return letter_blur_work_begin+slot*letter_blur_work_stride;
}
// effect_letter_blur.c, original cue 27. It captures the background in draw
// phase 0, then restores it and adds shifted copies of the text in phase 1.
std::uint32_t create_captured_blur(GuestMemory&,std::span<const std::uint32_t>);
void update_captured_blur(GuestMemory&,std::uint32_t task);
void release_captured_blur(GuestMemory&,std::uint32_t task);
FeedbackDraw draw_captured_blur(const GuestMemory&,std::uint32_t task,unsigned phase);
}
