#pragma once
#include "media_command.hpp"
#include "source_movie.hpp"
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace kx3 {
// 13CD20. The render pass submits a 640x224 GS readback only on the matching
// sampled field. destination and source field are explicit for the timeout
// branch which copies the same display field into both source buffers.
void capture_source_display_field(GuestMemory&,unsigned pass,unsigned display_field,
                                 const std::function<void(std::uint32_t,unsigned)>& submit);
enum class MediaDecodedKind : std::uint32_t { Image, Video, Audio, Data };

struct SourceMediaAsset {
    std::string original_name;       // Descriptor name, before source substitutions.
    std::string resolved_name;       // Name after source type/fallback substitutions.
    std::string virtual_name;        // Original directory prefix + resolved name.
    std::uint32_t source_type = 0;
    std::uint32_t source_size_bytes = 0; // 145958, NOT an asset ID.
    std::uint32_t flags = 0;
    MediaDecodedKind required_kind = MediaDecodedKind::Data;
    bool primary = false;
    bool preview_substitution = false;
    std::uint32_t source_audio_class = 0; // 140068: 0=file,1=SE,2=BGM.
    bool resident_record = true; // Original type-table+1C excludes PSS rows.
};
struct SourceAudioPlan {
    std::vector<std::string> prepare_bgm; // First type2 in original sorted order only.
    std::vector<std::uint32_t> retain_ids; // Final merged list, <=16.
    std::vector<std::uint32_t> source_pool_ids; // Source +DBC/+DC0 after metadata check.
};
struct SourceResourcePlan {
    std::string scene_token;
    std::string primary_virtual_name;
    std::string preview_virtual_name;
    std::vector<SourceMediaAsset> assets;
    SourceAudioPlan audio;
    bool fallback_primary = false;
};

struct MediaAssetReceipt {
    std::string virtual_name;
    std::string source_sha256;  // Hash of ORIGINAL encoded source, not derivative PNG.
    std::uint32_t source_size_bytes = 0;
    MediaDecodedKind decoded_kind = MediaDecodedKind::Data;
    std::uint64_t decoded_bytes = 0;
    std::uint32_t width = 0, height = 0;
    std::uint64_t frame_count = 0, sample_count = 0;
    bool reused_ready_cache = false;
};
struct MediaPrepareReceipt {
    std::uint64_t prepared_generation = 0; // Nonzero owned host prepared-state token.
    std::vector<MediaAssetReceipt> assets;
    std::vector<std::string> prepared_bgm;
    std::vector<std::uint32_t> retained_sound_ids;
    bool current_presentation_unchanged = false;
};

class DecodedImagePresenter {
public:
    virtual ~DecodedImagePresenter() = default;
    virtual bool has_decoded_primary(std::uint64_t generation) const noexcept = 0;
    virtual bool single_frame_committed(std::uint64_t generation) const noexcept = 0;
    virtual std::span<const MovieClipTiming> movie_timings(std::uint64_t generation) const noexcept = 0;
    virtual void stage_movie_frame(std::uint64_t generation,std::uint32_t member,std::uint32_t frame,bool loop) = 0;
    virtual void forget_staged_frame() noexcept = 0;
    virtual void capture_field(GuestMemory&, std::uint32_t destination, unsigned field) const = 0;
    virtual void commit_image(std::uint64_t generation) noexcept = 0;
};

class MediaActiveServices {
public:
    virtual ~MediaActiveServices() = default;
    // Query verified original encoded-file bytes via the source virtual mapping.
    // Zero means missing. Must not return decoded/PNG size.
    virtual std::uint32_t source_file_size(const std::string& virtual_name) const = 0;
    virtual std::vector<std::uint8_t> read_panel_member(const std::string&) const {
        throw std::runtime_error("Missing ISO panel resource provider");
    }
    // Original1B1598 bank-metadata flag, NOT "currently playing". Required only
    // for source SE dependencies, and must fail if metadata is unavailable.
    virtual bool sound_retention_flag(std::uint32_t sound_id) const = 0;
    // Prepare every planned asset and audio request, with no presentation switch.
    // A receipt is legal only after real I/O/decode/preload completion. Pending,
    // unavailable codecs and unsupported audio operations must throw.
    virtual MediaPrepareReceipt preload(const SourceResourcePlan&) = 0;
    virtual std::span<const std::uint8_t> sab_file(std::uint64_t,const std::string&) const { return {}; }
    // Called when receipt validation or guest writes fail. Drop this tentative
    // generation; old prepared/current state must remain intact.
    virtual void discard_prepared(std::uint64_t generation) noexcept = 0;
    virtual void rollback_prepared(std::uint64_t generation) noexcept { discard_prepared(generation); }
    virtual DecodedImagePresenter* image_presenter() noexcept { return nullptr; }
};

// Pure guest read + verified catalog queries. Original fields are published only
// after preload returns a valid receipt; caller still owns the RAM transaction.
SourceResourcePlan plan_active_media(GuestMemory&, const MediaRequest&, const MediaActiveServices&);
void validate_media_receipt(const SourceResourcePlan&, const MediaPrepareReceipt&);

bool resolve_preview_filename(GuestMemory&,const MediaActiveServices&,std::string& name,std::string& preview);
class SourceMediaActiveBackend final : public MediaCommandBackend {
public:
    struct Checkpoint {
        std::uint32_t pending_descriptor;
        std::uint64_t pending_generation,selected_generation;
        bool end_reported;
        MoviePosition movie{};
    };
    Checkpoint checkpoint() const;
    void restore_checkpoint(const Checkpoint&);
    void restore_preload(const std::string& token,std::uint64_t generation);
    explicit SourceMediaActiveBackend(MediaActiveServices& services) : services_(services) {}
    std::uint64_t execute_active(GuestMemory&, const MediaRequest&) override;
    std::vector<std::uint8_t> read_panel_member(const std::string& path) const override {
        return services_.read_panel_member(path);
    }
    void step_deferred(GuestMemory&) override;
    void finish_deferred(GuestMemory&) override;
    void adopt_completed_scene(const GuestMemory&) override;
    void consume_image_start(GuestMemory&) override;
    // Identifies assets selected by the completed 73; separate from a cue
    // starting visible playback. Zero until the group is committed.
    std::uint64_t selected_scene_generation() const noexcept { return selected_generation_; }
    const MoviePosition& movie_position() const noexcept {return movie_;}
    void begin_frame() override;
    void end_frame(bool commit) noexcept override;
private:
    MediaActiveServices& services_;
    bool frame_active_ = false;
    std::vector<std::uint64_t> frame_generations_;
    std::map<std::string,std::uint64_t> prefetched_,saved_prefetched_;
    struct Deferred { std::uint32_t descriptor=0; std::uint64_t generation=0; };
    Deferred pending_, saved_pending_;
    std::uint64_t selected_generation_=0, saved_selected_=0;
    std::uint64_t staged_presentation_=0;
    bool stream_end_reported_=false, saved_stream_end_reported_=false;
    MoviePosition movie_, saved_movie_;
};
}
