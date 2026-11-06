#include "../windows/project_audio.hpp"
#include <aaudio/AAudio.h>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
namespace kx3::platform::windows {
struct WaveOutput::Device {
    AAudioStream* stream=nullptr;
    std::mutex mutex;
    std::condition_variable changed;
    std::deque<StereoBlock> pending;
    bool closing=false;
    std::exception_ptr failure;
    std::atomic<std::uint32_t> frames{0};
    std::thread worker;
    void check(aaudio_result_t r,const char* what){if(r<0)throw std::runtime_error(std::string(what)+": "+AAudio_convertResultToText(r));}
    void run(){try{
        AAudioStreamBuilder* builder=nullptr;check(AAudio_createStreamBuilder(&builder),"Create audio");
        AAudioStreamBuilder_setDirection(builder,AAUDIO_DIRECTION_OUTPUT);
        AAudioStreamBuilder_setFormat(builder,AAUDIO_FORMAT_PCM_I16);
        AAudioStreamBuilder_setChannelCount(builder,2);AAudioStreamBuilder_setSampleRate(builder,48000);
        AAudioStreamBuilder_setSharingMode(builder,AAUDIO_SHARING_MODE_SHARED);
        AAudioStreamBuilder_setPerformanceMode(builder,AAUDIO_PERFORMANCE_MODE_NONE);
        const auto opened=AAudioStreamBuilder_openStream(builder,&stream);AAudioStreamBuilder_delete(builder);check(opened,"Open audio");
        if(AAudioStream_getSampleRate(stream)!=48000 || AAudioStream_getChannelCount(stream)!=2 || AAudioStream_getFormat(stream)!=AAUDIO_FORMAT_PCM_I16)
            throw std::runtime_error("Audio device did not accept 48 kHz stereo PCM");
        check(AAudioStream_requestStart(stream),"Start audio");
        for(;;){
            StereoBlock block;
            {std::unique_lock lock(mutex);changed.wait(lock,[&]{return closing||!pending.empty();});if(closing)break;
                block=pending.front();pending.pop_front();}changed.notify_all();
            int at=0;while(at<800){
                {std::lock_guard lock(mutex);if(closing)return;}
                const auto n=AAudioStream_write(stream,block.data()+2*at,800-at,100000000);
                check(n,"Write original audio");if(!n)throw std::runtime_error("Audio endpoint timed out");at+=n;
            }
            frames=std::uint32_t(AAudioStream_getFramesRead(stream));
        }
    }catch(...){std::lock_guard lock(mutex);failure=std::current_exception();changed.notify_all();}}
    ~Device(){
        {std::lock_guard lock(mutex);closing=true;}changed.notify_all();if(worker.joinable())worker.join();
        if(stream){AAudioStream_requestStop(stream);AAudioStream_close(stream);}
    }
};
WaveOutput::WaveOutput():device_(std::make_unique<Device>()){device_->worker=std::thread(&Device::run,device_.get());}
WaveOutput::~WaveOutput()=default;
void WaveOutput::submit(const StereoBlock& b){auto& d=*device_;std::unique_lock lock(d.mutex);
    d.changed.wait(lock,[&]{return d.pending.size()<4||d.failure||d.closing;});
    if(d.failure)std::rethrow_exception(d.failure);if(d.closing)throw std::runtime_error("Audio device is closing");
    d.pending.push_back(b);lock.unlock();d.changed.notify_all();}
std::uint32_t WaveOutput::played_frames()const{std::lock_guard lock(device_->mutex);if(device_->failure)std::rethrow_exception(device_->failure);return device_->frames.load();}
}
