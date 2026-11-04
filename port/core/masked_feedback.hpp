#pragma once
#include "field_feedback.hpp"
namespace kx3 {
struct MaskedFeedbackDraw {std::array<float,4> mask{};FeedbackDraw sprites;};
std::uint32_t create_masked_feedback(GuestMemory&,std::uint32_t heap,std::span<const std::uint32_t> args);
void update_masked_feedback(GuestMemory&,std::uint32_t task);
void release_masked_feedback(GuestMemory&,std::uint32_t task);
MaskedFeedbackDraw draw_masked_feedback(const GuestMemory&,std::uint32_t task,unsigned field);
}
