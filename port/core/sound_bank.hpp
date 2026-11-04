#pragma once
#include <cstdint>
#include <array>
#include <optional>
#include <span>
#include <vector>

namespace kx3 {
// A record and its stored streams refer to the verified SSDVDAT/se.dat.
// Stereo routing, ADSR and repeat playback belong to the voice/mixer.
struct SoundRecord {
    std::uint32_t offset, allocation, stream_bytes;
    std::uint16_t pitch, volume;
    std::uint8_t channels, flags;
    std::array<std::uint8_t,2> route_delays{};
};
struct SoundPcm {
    std::vector<std::int16_t> samples;
    std::optional<std::uint32_t> loop_start;
};
std::optional<SoundRecord> find_bank_sound(std::span<const std::uint8_t>, std::uint32_t id);
SoundPcm decode_bank_channel(std::span<const std::uint8_t>, const SoundRecord&, unsigned channel);
}
