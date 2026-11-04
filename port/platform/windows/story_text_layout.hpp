#pragma once
#include "window_drawing.hpp"
#include "../story_localization.hpp"
#include "../raster_frame.hpp"

namespace kx3::platform::windows {
// Coordinates remain relative to the original 640x448 layer. Returns the
// number of rows actually painted, excluding fully transparent source text.
struct TranslatedOptionHit { RECT rect;unsigned index; };
unsigned draw_story_translation(HDC dc,RECT stage,std::span<const LocalizedLine> lines,
                                std::vector<TranslatedOptionHit>& options);
RasterFrame raster_story_translation(HDC dc,std::span<const LocalizedLine> lines,
                                     std::vector<TranslatedOptionHit>& options);
}
