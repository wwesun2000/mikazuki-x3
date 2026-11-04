#pragma once
#include <cstdint>
#include <algorithm>
#include <span>
#include <stdexcept>

namespace kx3 {
struct MovieClipTiming {
    std::uint32_t frames, fps_num, fps_den;
    std::uint64_t video_start_sample=0,audio_start_sample=0,audio_frames=0;
};
struct MoviePosition {
    std::uint32_t member=0, frame=0, remainder=0;
    bool active=false, loop=false;
    std::uint64_t sample=0; // PSS 48 kHz presentation timeline.
    friend bool operator==(const MoviePosition&,const MoviePosition&)=default;
};
inline std::uint64_t pss_duration(const MovieClipTiming& c) {
    return std::max(c.audio_start_sample+c.audio_frames,
        c.video_start_sample+(std::uint64_t(c.frames)*48000*c.fps_den+c.fps_num-1)/c.fps_num);
}

// The Windows host's 60 Hz logical game clock drives original MPEG frame
// rate fractions. 198158 starts an MMV at member 0, then selects member 1.
// Only member 1 repeats while decoder bit 0 (+200) is set.
inline void advance_movie_clock(MoviePosition& p,std::span<const MovieClipTiming> clips) {
    if(!p.active)return;
    if(clips.empty() || clips.size()>2 || p.member>=clips.size())throw std::runtime_error("Unsupported MMV table");
    const auto current=clips[p.member];
    if(!current.fps_den || !current.fps_num || !current.frames || p.frame>=current.frames)
        throw std::runtime_error("Invalid source movie position");
    if(current.audio_frames){
        if(clips.size()!=1)throw std::runtime_error("Unsupported PSS audio in multipart clip");
        const auto end=pss_duration(current);
        if(p.sample>=end)throw std::runtime_error("Invalid source AV time");
        p.sample+=800;
        if(p.sample>=end){
            if(p.loop)p.sample%=end;
            else {p.sample=end;p.active=false;return;}
        }
        const auto since=p.sample>current.video_start_sample?p.sample-current.video_start_sample:0;
        p.frame=std::uint32_t(std::min<std::uint64_t>(current.frames-1,since*current.fps_num/(48000ull*current.fps_den)));
        return;
    }
    const std::uint64_t quantum=std::uint64_t(current.fps_den)*60;
    if(p.remainder>=quantum || current.fps_num>quantum)throw std::runtime_error("Unsupported frame clock");
    const std::uint64_t next=std::uint64_t(p.remainder)+current.fps_num;
    if(next<quantum) {p.remainder=static_cast<std::uint32_t>(next);return;}
    p.remainder=static_cast<std::uint32_t>(next-quantum);
    if(p.frame+1<current.frames) {++p.frame;return;}
    if(p.member+1<clips.size()) {
        if(clips[p.member+1].fps_num!=current.fps_num || clips[p.member+1].fps_den!=current.fps_den)
            throw std::runtime_error("MMV changes frame rate between members");
        ++p.member;p.frame=0;
    } else if(p.loop) p.frame=0;
    else p.active=false;
}
}
