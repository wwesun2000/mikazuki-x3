#include "project_audio.hpp"
#define NOMINMAX
#include <windows.h>
#include <mmsystem.h>
#include <algorithm>
#include <cmath>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace kx3::platform::windows {
namespace {
constexpr unsigned frames=800;
float gain(float from,float to,std::uint64_t at,std::uint64_t duration) {
    return at>=duration ? to : from+(to-from)*float(double(at)/double(duration));
}
bool finished(const PlayingVoice& v) {
    const auto& stream=v.sound->channels.at(v.stream);
    return (!v.loop && (v.position_q12>>12)>=stream.samples.size()) ||
           (v.stopping && v.ramp_elapsed>=v.ramp_length);
}
void check_mm(MMRESULT result,const char* action) {
    if(result!=MMSYSERR_NOERROR)
        throw std::runtime_error(std::string(action)+" (Windows audio error "+std::to_string(result)+")");
}
}

bool ProjectMixer::effect_active(std::uint32_t id) const {
    return std::any_of(voices_.begin(),voices_.end(),[&](const auto& voice){return voice.id==id && !finished(voice);});
}

void ProjectMixer::apply(std::span<const SourceSoundEvent> events,const ProjectImageServices& resources) {
    for(const auto& event:events) {
        if(event.action==SoundAction::Pitch){
            for(auto& v:voices_)if(v.id==event.id)v.pitch.set(event.pitch_multiplier,event.transition_ticks);
            continue;
        }
        const auto duration=std::uint64_t(event.transition_ticks)*frames;
        if(event.action==SoundAction::MusicVolume){
            if(music_ && !music_->stopping){
                auto& m=*music_;m.from=gain(m.from,m.to,m.ramp_elapsed,m.ramp_length);
                m.to=(float(event.music_volume)*.01f)*.8f*(float(m.track->volume)/16384.f);
                m.ramp_elapsed=0;m.ramp_length=duration;
            }
            continue;
        }
        if(event.action==SoundAction::PlayBgm) {
            if(music_ && !music_->stopping && music_->track->name==event.music_name)continue;
            const auto track=resources.prepared_music(event.music_name);
            if(!track)throw std::runtime_error("BGM was not prepared: "+event.music_name);
            // 1B42A8 -> 1B43A0 submits one replacement stream. 1B4508 clears
            // its starting gain before 1D124C installs the new stream and
            // 1D197C ramps that stream to the requested level.
            PlayingMusic music;music.track=track;music.ramp_length=duration;
            music.to=(float(event.music_volume)*.01f)*.8f*(float(track->volume)/16384.f);
            music_=std::move(music);continue;
        }
        if((event.action==SoundAction::StopBgm || event.action==SoundAction::StopAll) && music_){
            if(!duration)music_.reset();
            else {
                auto& track=*music_;track.from=gain(track.from,track.to,track.ramp_elapsed,track.ramp_length);
                track.to=0;track.ramp_elapsed=0;track.ramp_length=duration;track.stopping=true;
            }
        }
        if(event.action==SoundAction::StopBgm)continue;
        if(event.action==SoundAction::Pan || event.action==SoundAction::Volume){
            for(auto& v:voices_)if(v.id==event.id && !v.stopping){
                if(event.action==SoundAction::Pan)v.pan=event.pan;else v.volume=event.volume;
                if(v.volume==UINT32_MAX)throw std::runtime_error("Legacy voice has no saved volume routing");
                const auto target=source_pan_channel(v.sound->record,v.volume,v.pan,v.route,event.mono);
                v.left_begin=gain(v.left_begin,v.left_end,v.ramp_elapsed,v.ramp_length);
                v.right_begin=gain(v.right_begin,v.right_end,v.ramp_elapsed,v.ramp_length);
                v.left_end=target.left_gain;v.right_end=target.right_gain;
                v.ramp_elapsed=0;v.ramp_length=duration;
            }
            continue;
        }
        if(event.action==SoundAction::StopAll || event.action==SoundAction::StopEffects || event.action==SoundAction::Stop) {
            for(auto& v:voices_) if(event.action!=SoundAction::Stop || event.id==v.id) {
                v.left_begin=gain(v.left_begin,v.left_end,v.ramp_elapsed,v.ramp_length);
                v.right_begin=gain(v.right_begin,v.right_end,v.ramp_elapsed,v.ramp_length);
                v.left_end=v.right_end=0;v.ramp_elapsed=0;v.ramp_length=duration;
                v.stopping=true;
                if(v.delay)v.ramp_length=0;
            }
            std::erase_if(voices_,finished);
            continue;
        }
        const auto source=resources.sound_for_play(event.id);
        if(!source)throw std::runtime_error("Source sound requested before preparation: "+std::to_string(event.id));
        for(unsigned route=0;route<event.voices.size();++route) {
            const auto& channel=event.voices[route];
            if(channel.stream>=source->channels.size() || !std::isfinite(channel.left_gain) ||
               !std::isfinite(channel.right_gain) || !source->record.pitch)
                throw std::runtime_error("Invalid prepared source voice");
            const auto& pcm=source->channels[channel.stream];
            if(pcm.samples.empty() || (event.loop && (!pcm.loop_start || *pcm.loop_start>=pcm.samples.size())))
                throw std::runtime_error("Invalid prepared PCM loop");
            PlayingVoice v;
            v.id=event.id;v.sound=source;v.stream=channel.stream;v.loop=event.loop;
            v.route=route;v.volume=event.volume;v.pan=event.pan;
            v.delay=std::uint64_t(channel.delay_ticks)*frames;v.ramp_length=duration;
            v.left_end=channel.left_gain;v.right_end=channel.right_gain;
            voices_.push_back(std::move(v));
        }
    }
}

void ProjectMixer::restore_voices(std::vector<PlayingVoice> voices) {
    for(const auto& v:voices) {
        if(!std::isfinite(v.pitch.current) || !std::isfinite(v.pitch.target) || !std::isfinite(v.pitch.step) ||
           v.pitch.current<=0 || v.pitch.target<=0 ||
           !v.sound || v.route>1 || v.stream>=v.sound->channels.size() || !v.sound->record.pitch ||
           !std::isfinite(v.left_begin) || !std::isfinite(v.left_end) ||
           !std::isfinite(v.right_begin) || !std::isfinite(v.right_end) ||
           v.ramp_elapsed>v.ramp_length || v.position_q12>=(std::uint64_t(v.sound->channels[v.stream].samples.size())<<12) ||
           (v.loop && !v.sound->channels[v.stream].loop_start) || finished(v))
            throw std::runtime_error("Invalid saved sound voice");
    }
    voices_=std::move(voices);
}
void ProjectMixer::restore_music(std::optional<PlayingMusic> music) {
    if(music){
        const auto& m=*music;
        if(!m.track || !m.track->pcm.channels || m.frame>=m.track->pcm.interleaved.size()/m.track->pcm.channels ||
           (m.track->loop && m.frame>=m.track->loop_end) || m.ramp_elapsed>m.ramp_length ||
           !std::isfinite(m.from) || !std::isfinite(m.to))
            throw std::runtime_error("Invalid saved BGM voice");
    }
    music_=std::move(music);
}

StereoBlock ProjectMixer::mix_tick(const PreparedMovie* movie,const MoviePosition& position) {
    std::array<double,frames*2> mixed{};
    if(movie && movie->audio && position.active){
        const auto& c=movie->timing.at(position.member);
        const auto& pcm=movie->audio->interleaved;
        const auto duration=pss_duration(c);
        for(unsigned i=0;i<frames;++i){
            const auto absolute=position.sample+i;
            if(!position.loop && absolute>=duration)break;
            const auto when=absolute%duration;
            if(when<c.audio_start_sample || when-c.audio_start_sample>=c.audio_frames)continue;
            const auto at=(when-c.audio_start_sample)*2;
            mixed[2*i]=pcm[at];mixed[2*i+1]=pcm[at+1];
        }
    }
    if(music_) {
        auto& v=*music_;const auto& track=*v.track;const auto& pcm=track.pcm;
        const auto end=track.loop?std::size_t(track.loop_end):pcm.interleaved.size()/pcm.channels;
        for(unsigned i=0;i<frames;++i) {
            const double level=gain(v.from,v.to,v.ramp_elapsed,v.ramp_length);
            mixed[2*i]+=level*pcm.interleaved[v.frame*pcm.channels];
            mixed[2*i+1]+=level*pcm.interleaved[v.frame*pcm.channels+pcm.channels-1];
            ++v.frame;
            if(v.ramp_elapsed<v.ramp_length)++v.ramp_elapsed;
            if(v.stopping && v.ramp_elapsed>=v.ramp_length){music_.reset();break;}
            if(v.frame==end){
                if(!track.loop){music_.reset();break;}
                v.frame=track.loop_start;
            }
        }
    }
    for(auto& v:voices_) {
        v.pitch.advance();
        const auto pitch=source_pitch_register(v.sound->record.pitch,v.pitch.current);
        const auto& pcm=v.sound->channels[v.stream];
        const auto length=std::uint64_t(pcm.samples.size())<<12;
        for(unsigned frame=0;frame<frames;++frame) {
            if(finished(v))break;
            if(v.delay){--v.delay;continue;}
            const auto i=std::size_t(v.position_q12>>12);
            const auto next=i+1<pcm.samples.size()?i+1:(v.loop?std::size_t(*pcm.loop_start):i);
            const double sample=pcm.samples[i]+(pcm.samples[next]-pcm.samples[i])*double(v.position_q12&4095u)/4096.0;
            mixed[2*frame]+=sample*gain(v.left_begin,v.left_end,v.ramp_elapsed,v.ramp_length);
            mixed[2*frame+1]+=sample*gain(v.right_begin,v.right_end,v.ramp_elapsed,v.ramp_length);
            if(v.ramp_elapsed<v.ramp_length)++v.ramp_elapsed;
            v.position_q12+=pitch;
            if(v.loop && v.position_q12>=length) {
                const auto start=std::uint64_t(*pcm.loop_start)<<12;
                v.position_q12=start+(v.position_q12-length)%(length-start);
            }
        }
    }
    std::erase_if(voices_,finished);
    StereoBlock block{};
    for(std::size_t i=0;i<block.size();++i)
        block[i]=std::int16_t(std::lround(std::clamp(mixed[i],-32768.0,32767.0)));
    return block;
}

struct WaveOutput::Device {
    struct Slot { std::array<StereoBlock,2> data{}; WAVEHDR header{}; bool prepared=false; };
    std::array<Slot,3> slots{};
    HWAVEOUT handle=nullptr;
    HANDLE event=nullptr;
    std::size_t next=0;
    std::mutex lock;
    std::condition_variable changed;
    std::deque<StereoBlock> pending;
    std::exception_ptr failure;
    bool closing=false,opened=false;
    std::thread worker;
    void open();
    void pump();
    ~Device() {
        {std::lock_guard guard(lock);closing=true;}
        changed.notify_all();
        if(worker.joinable())worker.join();
        if(handle) {
            waveOutReset(handle);
            for(auto& slot:slots)if(slot.prepared)waveOutUnprepareHeader(handle,&slot.header,sizeof(slot.header));
            waveOutClose(handle);
        }
        if(event)CloseHandle(event);
    }
};
void WaveOutput::Device::open(){
    event=CreateEventW(nullptr,FALSE,FALSE,nullptr);
    if(!event)throw std::runtime_error("Cannot create Windows audio completion event");
    WAVEFORMATEX format{WAVE_FORMAT_PCM,2,48000,192000,4,16,0};
    check_mm(waveOutOpen(&handle,WAVE_MAPPER,&format,reinterpret_cast<DWORD_PTR>(event),0,CALLBACK_EVENT),"Open stereo output");
    for(auto& slot:slots) {
        slot.header.lpData=reinterpret_cast<char*>(slot.data.data());slot.header.dwBufferLength=sizeof(slot.data);
        check_mm(waveOutPrepareHeader(handle,&slot.header,sizeof(slot.header)),"Prepare output buffer");
        slot.prepared=true;
    }
}
void WaveOutput::Device::pump(){
    try{
        open();
        std::unique_lock guard(lock);opened=true;
        while(true){
            changed.wait(guard,[&]{return closing || !pending.empty();});
            if(closing)return;
            auto& slot=slots[next];
            guard.unlock();
            while(slot.header.dwFlags&WHDR_INQUEUE){
                if(WaitForSingleObject(event,250)!=WAIT_OBJECT_0)
                    throw std::runtime_error("Windows audio stream did not consume its queued PCM");
            }
            guard.lock();
            if(closing)return;
            const auto count=std::min(slot.data.size(),pending.size());
            for(unsigned i=0;i<count;++i){slot.data[i]=pending.front();pending.pop_front();}
            slot.header.dwBufferLength=DWORD(count*sizeof(StereoBlock));
            guard.unlock();changed.notify_all();
            check_mm(waveOutWrite(handle,&slot.header,sizeof(slot.header)),"Submit original audio");
            next=(next+1)%slots.size();
            guard.lock();
        }
    }catch(...){
        std::lock_guard guard(lock);failure=std::current_exception();changed.notify_all();
    }
}
WaveOutput::WaveOutput():device_(std::make_unique<Device>()) {
    device_->worker=std::thread(&Device::pump,device_.get());
}
WaveOutput::~WaveOutput()=default;
std::uint32_t WaveOutput::played_frames() const {
    {
        std::lock_guard guard(device_->lock);
        if(device_->failure)std::rethrow_exception(device_->failure);
        if(!device_->opened)return 0;
    }
    MMTIME position{};
    position.wType=TIME_SAMPLES;
    check_mm(waveOutGetPosition(device_->handle,&position,sizeof(position)),"Read audio playback position");
    if(position.wType==TIME_SAMPLES)return position.u.sample;
    if(position.wType==TIME_BYTES)return position.u.cb/4; // PCM16 stereo
    if(position.wType==TIME_MS)return position.u.ms*48;
    throw std::runtime_error("Windows audio endpoint returned an unsupported clock unit");
}
void WaveOutput::submit(const StereoBlock& samples) {
    auto& d=*device_;
    // Keep order and apply back-pressure only if the endpoint really falls
    // behind. Driver calls and its 10/20-ms service quantum stay off the UI.
    std::unique_lock guard(d.lock);
    d.changed.wait(guard,[&]{return d.pending.size()<4 || d.failure;});
    if(d.failure)std::rethrow_exception(d.failure);
    d.pending.push_back(samples);
    guard.unlock();d.changed.notify_all();
}
}
