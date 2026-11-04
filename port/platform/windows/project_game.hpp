#pragma once
#include "../../core/captured_blur.hpp"
#include "project_media.hpp"
#include "project_audio.hpp"
#include "../../core/manager_bootstrap.hpp"
#include "../../core/story_frame.hpp"
#include "../../core/actor_choice.hpp"
#include "../../core/card_volume.hpp"
#include "../../core/title_selection.hpp"
#include <string_view>

namespace kx3::platform::windows {
// An independently owned new-game session. No emulator RAM or save fixture
// enters this path. The constructor publishes nothing if source validation fails.
class ProjectGame {
public:
    explicit ProjectGame(const std::filesystem::path& root, std::string_view scenario,
                         std::optional<std::uint32_t> clock_seed=std::nullopt);
    StoryFrameResult advance(std::optional<ChoiceInput> input = std::nullopt);
    TitleAction title_input(TitleSelection&,std::uint16_t,std::vector<SourceSoundEvent>&);
    void enter_label_for_probe(std::uint32_t selector,std::uint32_t name_file_offset);
    void enter_record_for_probe(std::uint32_t selector,std::uint32_t file_offset);
    void prepare_choice_layout_for_probe();
    void enter_staff_roll_for_probe();
    const GuestMemory& memory() const { return memory_; }
    const ColdDispatchRuntime& runtime() const { return runtime_; }
    ActorChoiceView actor_choice() const {return actor_choice_view(memory_,runtime_.manager);}
    const ProjectImageServices& images() const { return images_; }
    // The original pass-0 visual tasks precede both Japanese glyphs and
    // localized text. Returns the same immutable scene for a completed tick.
    std::shared_ptr<const RasterFrame> scene_frame() const;
    FeedbackDraw text_blur() const;
    // 1013F0 calls the original task pass 1 after the text layer.
    std::shared_ptr<const RasterFrame> foreground_frame() const;
    std::span<const TextGlyphEvent> visible_text_events() const { return visible_text_; }
    const StereoBlock& last_audio() const { return audio_block_; }
    const ProjectMixer& mixer() const { return mixer_; }
    void enable_audio_output() { audio_enabled_=true; audio_error_.clear(); }
    void set_system_record_file(std::filesystem::path file);
    const std::string& record_export_error() const {return record_export_error_;}
    std::span<const std::uint8_t> last_system_record() const {return last_system_record_;}
    const std::string& audio_output_error() const { return audio_error_; }
    std::int64_t output_submit_us() const {return output_submit_us_;}
    std::uint32_t played_audio_frames() const { return output_?output_->played_frames():0; }
    void save(const std::filesystem::path& destination) const;
    void save_from_menu(const std::filesystem::path& destination) const;
    void save_auto_target(const std::filesystem::path& destination,std::uint32_t slot);
    static std::unique_ptr<ProjectGame> load(const std::filesystem::path& root,std::string_view scenario,
                                             const std::filesystem::path& source);
    static std::unique_ptr<ProjectGame> load_note(const std::filesystem::path& root,std::string_view scenario,
                                                 const std::filesystem::path& system_record,unsigned slot);
    static std::vector<unsigned> note_slots(const std::filesystem::path& root,std::string_view scenario,
                                            const std::filesystem::path& system_record);
    static std::unique_ptr<ProjectGame> new_note(const std::filesystem::path& root,std::string_view scenario,
                                                 const std::filesystem::path& system_record,unsigned slot,bool replace);
    std::uint64_t logical_tick() const { return logical_tick_; }
private:
    void save_impl(const std::filesystem::path&,bool resume_story,std::optional<std::uint32_t> target=std::nullopt,
                   bool record_committed=false) const;
    void export_record(std::span<const std::uint8_t>);
    void reconcile_loaded_record();
    void install_system_tables(const std::filesystem::path& root);
    std::string scenario_;
    GuestMemory memory_;
    ColdDispatchRuntime runtime_;
    ProjectImageServices images_;
    SourceMediaActiveBackend backend_;
    StoryFrameDriver driver_;
    ProjectMixer mixer_;
    StereoBlock audio_block_{};
    std::unique_ptr<WaveOutput> output_;
    bool audio_enabled_=false;
    std::string audio_error_;
    std::int64_t output_submit_us_=0;
    std::filesystem::path system_record_file_;
    std::filesystem::path loaded_checkpoint_;
    std::string loaded_checksum_,record_export_error_;
    CardVolume card_;
    bool autosave_to_original_card_=false;
    std::vector<std::uint8_t> last_system_record_;
    bool frame_complete_=false;
    bool workers_done_=false;
    std::optional<StoryFrameResult> pending_manager_frame_;
    std::uint64_t logical_tick_=0;
    std::vector<TextGlyphEvent> visible_text_;
    mutable std::uint64_t composed_tick_=UINT64_MAX;
    mutable std::shared_ptr<const RasterFrame> composed_scene_;
    mutable std::uint64_t foreground_tick_=UINT64_MAX;
    mutable std::shared_ptr<const RasterFrame> foreground_;
    std::vector<std::uint8_t> snow_ctf_;
    std::vector<std::uint8_t> circle_ctf_;
};
}
