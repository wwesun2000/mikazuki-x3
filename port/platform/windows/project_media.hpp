#pragma once
#include "../../core/media_active.hpp"
#include "../../core/sound_bank.hpp"
#include "../raster_frame.hpp"
#include <filesystem>
#include <map>
#include <memory>
#include "project_movie.hpp"
#include "source_codec.hpp"

namespace kx3::platform::windows {
// Host reservations, independent of the number of requests in a PS2 file batch.
inline constexpr std::uint64_t prepared_media_budget=256ull<<20;
inline constexpr std::uint64_t scene_surface_reserve=640*448*4;
inline constexpr unsigned max_prepared_scenes=unsigned(prepared_media_budget/scene_surface_reserve);
struct PreparedSound {
    SoundRecord record;
    std::string source_hash;
    std::vector<SoundPcm> channels;
    std::uint64_t samples=0;
};
struct PreparedImages {
    SourceResourcePlan plan;
    std::map<std::string,std::shared_ptr<const RasterFrame>> frames;
    std::map<std::string,std::vector<std::uint8_t>> animations;
    std::shared_ptr<const PreparedMovie> movie;
    std::map<std::uint32_t,std::shared_ptr<const PreparedSound>> sounds;
    struct Music {
        std::string name, source_hash;
        MusicPcm pcm;
        std::uint32_t loop_start=0, loop_end=0, volume=0;
        bool loop=false;
    };
    std::map<std::string,std::shared_ptr<const Music>> music;
};
// Uses source-bound cache catalog, never scene screenshots or token-specific
// behavior. Currently implements certified single-frame image resources only.
class ProjectImageServices final : public MediaActiveServices, private DecodedImagePresenter {
public:
    explicit ProjectImageServices(std::filesystem::path project_root):root_(std::move(project_root)){}
    std::uint32_t source_file_size(const std::string&) const override;
    std::vector<std::uint8_t> read_panel_member(const std::string&) const override;
    bool sound_retention_flag(std::uint32_t) const override;
    MediaPrepareReceipt preload(const SourceResourcePlan&) override;
    std::span<const std::uint8_t> sab_file(std::uint64_t,const std::string&) const override;
    void discard_prepared(std::uint64_t generation) noexcept override;
    void rollback_prepared(std::uint64_t generation) noexcept override;
    const std::map<std::uint64_t,PreparedImages>& prepared() const noexcept {return prepared_;}
    std::uint64_t current_generation() const noexcept {return current_generation_;}
    std::shared_ptr<const PreparedSound> prepared_sound(std::uint32_t id) const noexcept;
    std::shared_ptr<const PreparedSound> open_bank_sound(std::uint32_t id) const;
    std::shared_ptr<const PreparedSound> sound_for_play(std::uint32_t id) const;
    std::shared_ptr<const PreparedImages::Music> prepared_music(const std::string&) const;
    std::shared_ptr<const PreparedImages::Music> open_music(const std::string&) const;
    void restore_prepared(std::uint64_t id,const SourceResourcePlan&);
    void restore_display(std::uint64_t visible,std::uint64_t next,bool release_after_display,
                         std::uint32_t member=0,std::uint32_t frame=0);
    std::uint32_t visible_member() const noexcept { return visible_member_; }
    std::uint32_t visible_frame() const noexcept { return visible_frame_; }
    std::uint64_t next_generation() const { return next_generation_; }
    bool release_after_display() const { return release_after_display_; }
    std::shared_ptr<const RasterFrame> current_frame() const noexcept {return current_frame_;}
    DecodedImagePresenter* image_presenter() noexcept override { return this; }
private:
    std::span<const std::uint8_t> verified_bank() const;
    mutable std::vector<std::uint8_t> bank_;
    mutable std::map<std::uint32_t,std::shared_ptr<const PreparedSound>> menu_sounds_;
    bool has_decoded_primary(std::uint64_t generation) const noexcept override;
    bool single_frame_committed(std::uint64_t generation) const noexcept override {
        return current_frame_ && current_generation_==generation;
    }
    void capture_field(GuestMemory&, std::uint32_t destination, unsigned field) const override;
    std::span<const MovieClipTiming> movie_timings(std::uint64_t generation) const noexcept override;
    void stage_movie_frame(std::uint64_t generation,std::uint32_t member,std::uint32_t frame,bool loop) override;
    void forget_staged_frame() noexcept override { staged_frame_.reset(); staged_generation_=0; }
    std::uint64_t staged_generation_=0;
    std::uint32_t staged_member_=0,staged_number_=0,visible_member_=0,visible_frame_=0;
    std::shared_ptr<const RasterFrame> staged_frame_;
    void commit_image(std::uint64_t generation) noexcept override;
    std::shared_ptr<const RasterFrame> current_frame_;
    std::filesystem::path root_;
    std::uint64_t next_generation_=1,current_generation_=0;
    bool release_after_display_=false;
    std::map<std::uint64_t,PreparedImages> prepared_;
};
}
