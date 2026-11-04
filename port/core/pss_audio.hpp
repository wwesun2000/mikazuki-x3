#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace kx3 {
struct PssPcm {
    std::uint32_t rate=0,channels=0;
    std::uint64_t first_audio_pts90k=0,first_video_pts90k=0;
    std::int64_t audio_offset90k=0; // Signed audio start relative to the first video PTS.
    std::vector<std::int16_t> interleaved;
};
std::optional<PssPcm> decode_pss_audio(std::span<const std::uint8_t> source);
}
