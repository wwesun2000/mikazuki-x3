#pragma once
#include "choice_pipeline.hpp"
#include <optional>

namespace kx3 {
// Ordinary option hit testing in original 640x448 logical coordinates.
std::optional<std::uint32_t> source_choice_at(const GuestMemory&,std::uint32_t manager,int x,int y);
// Once per actual presentation tick, independently of manager script steps.
void advance_source_glyphs(GuestMemory&,std::uint32_t font);
}
