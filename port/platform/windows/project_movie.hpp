#pragma once
#include "../raster_frame.hpp"
#include "../../core/source_movie.hpp"
#include "../../core/pss_audio.hpp"
#include "source_codec.hpp"
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace kx3::platform::windows {
struct PreparedMovie {
    std::vector<MovieClipTiming> timing;
    std::vector<std::shared_ptr<MovieReader>> clips;
    std::uint64_t total_frames=0;
    std::uint64_t decoder_reserve=0;
    std::string source_hash;
    std::optional<PssPcm> audio;
    std::shared_ptr<const RasterFrame> load(std::uint32_t member,std::uint32_t frame,
                                            bool playing=false,bool loop=false) const;
};
std::shared_ptr<const PreparedMovie> prepare_original_movie(const std::filesystem::path& root,
    const std::string& virtual_name,std::uint32_t source_size);
}
