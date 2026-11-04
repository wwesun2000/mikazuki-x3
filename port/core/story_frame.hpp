#pragma once
#include "choice_pipeline.hpp"
#include "text_driver.hpp"
#include "system_menu.hpp"
#include <mutex>
#include <optional>

namespace kx3 {
class MediaCommandBackend;
class MediaActiveServices;
struct StoryFrameResult {
    std::uint32_t script_steps=0;
    bool input_or_context_blocked=false;
    bool timer_pending=false;
    std::vector<TextGlyphEvent> glyphs;
    std::optional<std::size_t> last_page_clear; // Index in glyphs at the last 1114F8.
    std::vector<ChoiceEffect> choice_effects;
    std::vector<SourceSoundEvent> system_sounds;
    bool system_record_requested=false;
};
// Observes the source manager's actual calls and runs platform inputs and
// panel tasks while its original three semaphores are held.
struct ManagerFrameBindings {
    StoryFrameResult& result;
    bool menu_was_open;
    void sample(GuestMemory&,ExecutionServices&) const;
    void finish(GuestMemory&,std::uint32_t manager,ExecutionServices&) const;
};

// One instance per native session. Frame results are handed to presentation
// only after all guest writes and host preparation in this frame succeed.
class StoryFrameDriver {
public:
    StoryFrameResult advance(GuestMemory&, std::uint32_t manager, MediaCommandBackend*,
                             ChoiceServices* choice=nullptr, std::optional<ChoiceInput> input=std::nullopt,
                             const SystemMenuHost* system_menu=nullptr,std::uint32_t screen_task_heap=0,
                             const SoundDeviceStatus* sound_device=nullptr,const MediaActiveServices* iso_files=nullptr);
private:
    std::mutex session_lock_;
};
}
