#pragma once
#include "../raster_frame.hpp"
#include <algorithm>
#include <filesystem>
#include <memory>
#include <span>

namespace kx3::platform::windows {
inline std::size_t movie_lookahead_frames(std::size_t frame_bytes,std::uint32_t count){
    return std::min<std::size_t>(count,std::clamp<std::size_t>((8u<<20)/frame_bytes,1,8));
}
// Decode a verified original single-frame ipum member to tightly packed RGBA.
std::shared_ptr<const RasterFrame> decode_original_ipu(const std::filesystem::path& project,
                                                      std::vector<std::uint8_t> source);
struct MusicPcm {
    std::vector<std::int16_t> interleaved;
    std::uint32_t channels=0, rate=0;
};
MusicPcm decode_original_vorbis(const std::filesystem::path& project,std::span<const std::uint8_t> source);
class MovieReader {
public:
    MovieReader(const std::filesystem::path& project,std::span<const std::uint8_t> encoded,bool program_stream,
                std::uint32_t width,std::uint32_t height,std::uint32_t frames);
    ~MovieReader();
    void prime(bool loop);
    std::shared_ptr<const RasterFrame> read(std::uint32_t frame,bool playing,bool loop);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}
