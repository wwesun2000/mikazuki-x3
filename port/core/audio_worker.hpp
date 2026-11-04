#pragma once
#include <cstdint>
#include <array>
#include <functional>
#include <vector>
#include <string>
#include "sound_bank.hpp"

namespace kx3 {
class SoundDeviceStatus {
public:
    virtual ~SoundDeviceStatus() = default;
    virtual bool effect_active(std::uint32_t id) const = 0;
};
class GuestMemory;
enum class SoundAction { Play, StopAll, StopBgm, Stop, PlayBgm, Pan, Volume, MusicVolume, StopEffects, Pitch };
struct SourceSoundVoice {
    std::uint32_t stream=0, delay_ticks=0;
    float left_gain=0, right_gain=0;
};
struct SourceSoundEvent {
    SoundAction action=SoundAction::Play;
    std::uint32_t id=0, transition_ticks=0;
    bool loop=false;
    std::array<SourceSoundVoice,2> voices{};
    std::string music_name;
    std::uint32_t music_volume=0;
    std::uint32_t volume=0;
    std::int32_t pan=0;
    float pitch_multiplier=1;
    bool mono=false;
};
SourceSoundVoice source_pan_channel(const SoundRecord&,std::uint32_t volume,std::int32_t pan,unsigned route,bool mono);
using SoundLookup=std::function<const SoundRecord*(std::uint32_t)>;
// Direct 1B15F0 interface used by the game system menu, before host output.
SourceSoundEvent system_sound(GuestMemory&,std::uint32_t id,std::uint32_t volume,const SoundLookup&);
std::vector<SourceSoundEvent> service_audio_worker(GuestMemory&,const SoundLookup&);
// Single-owner native adapter for the original 13F808 worker on a silent sound
// device. Requires an idle device; an unsupported command leaves the batch intact.
std::uint32_t service_idle_audio_worker(GuestMemory&);
}
