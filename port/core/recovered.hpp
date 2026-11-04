#pragma once
#include <cstdint>
#include <vector>

namespace kx3 {
// Address bindings identify recovered source routines, never native pointers.
class GuestMemory;
class ChoiceServices;
class MediaCommandBackend;
class TextPresentationBackend;
struct ChoiceInput;
struct ChoiceEffect;
struct SystemMenuHost;
struct SourceSoundEvent;
class SoundDeviceStatus;
class CardVolume;
class MediaActiveServices;
struct ManagerFrameBindings;
struct ExecutionServices {
    ChoiceServices* choice = nullptr;
    MediaCommandBackend* media = nullptr;
    TextPresentationBackend* text = nullptr;
    const ChoiceInput* choice_input = nullptr;
    std::vector<ChoiceEffect>* choice_effects = nullptr;
    const SystemMenuHost* system_menu = nullptr;
    std::vector<SourceSoundEvent>* system_sounds = nullptr;
    std::uint32_t screen_task_heap = 0;
    bool* system_record_requested = nullptr;
    const SoundDeviceStatus* sound_device = nullptr;
    CardVolume* card = nullptr;
    ManagerFrameBindings* manager_frame = nullptr;
    const MediaActiveServices* iso_files = nullptr;
    const std::uint16_t* title_buttons = nullptr; // Focused native work selector, 170658 output.
};
std::uint64_t invoke_recovered(GuestMemory& memory, std::uint32_t entry,
                                      std::uint32_t self, std::uint64_t a1 = 0,
                                      std::uint64_t a2 = 0, std::uint64_t a3 = 0,
                                      ExecutionServices* services = nullptr);
}
