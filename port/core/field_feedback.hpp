#pragma once
#include "screen_zoom.hpp"
#include <vector>
namespace kx3 {
struct FeedbackSprite {ZoomDraw coordinates;unsigned alpha=0;};
using FeedbackDraw=std::vector<FeedbackSprite>;
std::uint32_t create_field_feedback(GuestMemory&,std::uint32_t heap,std::span<const std::uint32_t> args);
void update_field_feedback(GuestMemory&,std::uint32_t task);
void release_field_feedback(GuestMemory&,std::uint32_t task);
FeedbackDraw draw_field_feedback(const GuestMemory&,std::uint32_t task,unsigned field);
}
