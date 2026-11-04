#pragma once
#include "audio_worker.hpp"
#include "recovered.hpp"
#include <optional>

namespace kx3 {
enum class SystemMenuAction : std::uint32_t { Endings=0, Settings=1, Memory=2, SaveAndQuit=3, Timeline=4, Chapters=5 };
struct SystemMenuView {
    bool open=false, can_request_save=false, settings_notice=false;
    std::uint32_t screen=0,focus=0;
    std::uint32_t subfocus=0;
    std::uint32_t interval_level=0; // +1C of the active 223C70 object.
    bool interval_ready=false, can_stop_auto=false;
    std::uint32_t notice_text_address=0;
    bool controls_visible=false;
    bool brightness_visible=false;
    std::uint32_t brightness_level=0;
    std::array<std::uint32_t,4> settings{}; // Original 1A2A18 option order.
    std::vector<SystemMenuAction> actions;
};
struct SystemMenuHost {
    // Caller reserves four guest heap bytes before starting the session.
    // 121648 constructs this object only when its singleton is first needed.
    std::uint32_t context_storage=0;
    SoundLookup sounds;
};
SystemMenuView system_menu_view(const GuestMemory&,std::uint32_t manager);
// Mirrors 121E50's normal physical-triangle eligibility without simulating
// an edge. An unknown context or the mutating autoplay path has no prediction.
std::optional<bool> system_menu_available(const GuestMemory&,std::uint32_t manager);
std::optional<bool> brightness_control_available(const GuestMemory&,std::uint32_t manager);
std::optional<bool> inspection_control_available(const GuestMemory&,std::uint32_t manager);
// Call only on the detached RAM image that will become the persisted PC save.
// The live session remains at card confirmation if persistence later fails.
void prepare_system_save_resume(GuestMemory&,std::uint32_t manager);
// Original auto-save target success after port 0 / zero-based PC card slot.
// Use resume_story on the detached copy persisted to disk; apply false to
// the live session only after the native card write commits.
void complete_auto_save_target(GuestMemory&,std::uint32_t manager,std::uint32_t slot,bool resume_story);
void advance_system_menu(GuestMemory&,std::uint32_t manager,ExecutionServices*);
void retire_interval_tasks(GuestMemory&,std::uint32_t heap);
bool has_system_menu(std::uint32_t) noexcept;
std::uint64_t invoke_system_menu(GuestMemory&,std::uint32_t entry,std::uint32_t self,
                                 std::uint64_t a1,std::uint64_t a2,std::uint64_t a3,ExecutionServices*);
}
