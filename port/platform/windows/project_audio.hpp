#pragma once
#include "../../core/sound_parameters.hpp"
#include "../../core/audio_worker.hpp"
#include "project_media.hpp"
#include <array>

namespace kx3::platform::windows {
using StereoBlock=std::array<std::int16_t,1600>; // 800 stereo frames at 48 kHz
struct PlayingVoice {
    SoundPitch pitch;
    std::shared_ptr<const PreparedSound> sound;
    std::uint64_t position_q12=0, delay=0, ramp_elapsed=0, ramp_length=0;
    std::uint32_t id=0, stream=0, route=0, volume=UINT32_MAX;
    std::int32_t pan=0;
    float left_begin=0, right_begin=0, left_end=0, right_end=0;
    bool loop=false, stopping=false;
};
struct PlayingMusic {
    std::shared_ptr<const PreparedImages::Music> track;
    std::uint64_t frame=0, ramp_elapsed=0, ramp_length=0;
    float from=0,to=0;
    bool stopping=false;
};

// Copying this state shares immutable PCM. A worker may stage a whole audio
// block, then publish it only after guest/loader transactions succeed.
class ProjectMixer : public SoundDeviceStatus {
public:
    bool effect_active(std::uint32_t id) const override;
    void apply(std::span<const SourceSoundEvent>,const ProjectImageServices&);
    StereoBlock mix_tick(const PreparedMovie* movie=nullptr,const MoviePosition& position={});
    const std::vector<PlayingVoice>& voices() const { return voices_; }
    void restore_voices(std::vector<PlayingVoice>);
    const std::optional<PlayingMusic>& music() const { return music_; }
    void restore_music(std::optional<PlayingMusic>);
private:
    std::vector<PlayingVoice> voices_;
    std::optional<PlayingMusic> music_;
};

class WaveOutput {
public:
    WaveOutput();
    ~WaveOutput();
    WaveOutput(const WaveOutput&)=delete;
    WaveOutput& operator=(const WaveOutput&)=delete;
    void submit(const StereoBlock&);
    std::uint32_t played_frames() const;
private:
    struct Device;
    std::unique_ptr<Device> device_;
};
}
