#include "../core/audio_worker.hpp"
#include "../core/guest_memory.hpp"
#include <fstream>
#include <iostream>

namespace {
void check(bool ok,const char* why){if(!ok)throw std::runtime_error(why);}
}
int main(int argc,char** argv){
    try {
        if(argc!=2)throw std::runtime_error("Pass original se.dat");
        std::ifstream file(argv[1],std::ios::binary|std::ios::ate);
        const auto size=file.tellg();
        check(file && size>0 && size<256*1024*1024,"Invalid sound bank");
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        file.seekg(0);check(bool(file.read(reinterpret_cast<char*>(bytes.data()),size)),"Bank read error");
        const auto record=kx3::find_bank_sound(bytes,537002);
        check(record.has_value() && record->pitch==2048,"Original loop record missing");
        const auto lookup=[&](std::uint32_t id){return id==537002?&*record:nullptr;};
        kx3::GuestMemory m;
        m.write_u32(0x207c08,1); // Original 15DE08 stereo default.
        constexpr std::uint32_t q=0x23d3a0,id=537002,args=q+280;
        m.write_u32(q+4,1);m.write_u32(q+8,0x140478);
        m.write_u32(args,id);m.write_u32(args+4,80);m.write_u32(args+8,240);
        auto v=kx3::service_audio_worker(m,lookup);
        check(v.size()==1 && v[0].action==kx3::SoundAction::Play && v[0].loop && v[0].id==id &&
              v[0].transition_ticks==240 && m.read_u32(0x2389e0)==1 && m.read_u32(0x1e4c680)==id,
              "Initial source play/loop mismatch");
        const auto& voices=v[0].voices;
        for(unsigned route=0;route<2;++route){
            const auto mono=kx3::source_pan_channel(*record,80,-100,route,true);
            check(mono.left_gain==10240.0f/16384 && mono.right_gain==mono.left_gain,
                  "Original IRX mono gain differs for extreme pan");
        }
        check(voices[0].delay_ticks==0 && voices[1].delay_ticks==14 &&
              voices[0].stream==0 && voices[1].stream==0,"Source voice starts mismatch");
        check(voices[0].left_gain==9600.0f/16384 && voices[0].right_gain==800.0f/16384 &&
              voices[1].left_gain==800.0f/16384 && voices[1].right_gain==9600.0f/16384,
              "SSDV target stereo gains mismatch");
        m.write_u32(q,0);
        check(kx3::service_audio_worker(m,lookup).empty() && m.read_u32(0x2389e0)==1,
              "Existing loop restarted");
        m.write_u32(q,0);m.write_u32(q+8,0x140540);m.write_u32(args+4,6);m.write_u32(args+8,0);
        v=kx3::service_audio_worker(m,lookup);
        check(v.size()==1 && v[0].action==kx3::SoundAction::Stop && v[0].transition_ticks==6 &&
              !m.read_u32(0x2389e0) && m.read_u32(0x1e4c680)==0xffffffffu,"Explicit stop mismatch");
        // 1B1858 enqueues the fade first, waits transition+1 VBlanks, then
        // releases both the loop-list entry and the 13F808 worker counter.
        m.write_u32(q,0);m.write_u32(q+4,2);m.write_u32(args,313171);m.write_u32(args+4,30);m.write_u32(args+8,1);
        m.write_u32(q+12,0x140478);m.write_u32(args+48,id);m.write_u32(args+52,60);
        m.write_u32(0x238730,1);m.write_u32(0x2389e0,1);m.write_u32(0x1e4c680,313171);
        v=kx3::service_audio_worker(m,lookup);
        check(v.size()==1 && v.front().id==313171 && v.front().transition_ticks==30 &&
              m.read_u32(q)==0 && m.read_u32(0x238730)==1,"Blocking SE fade was not submitted");
        for(unsigned i=0;i<30;++i)
            check(kx3::service_audio_worker(m,lookup).empty() && !m.read_u32(q) && m.read_u32(0x238730)==1 &&
                  m.read_u32(0x1e4c680)==313171,"Worker released during 1B0958");
        v=kx3::service_audio_worker(m,lookup);
        check(v.size()==1 && v.front().action==kx3::SoundAction::Play && v.front().id==id &&
              m.read_u32(q)==2 && !m.read_u32(0x238730) && m.read_u32(0x1e4c680)==id,"Worker did not resume at the next ring entry");
        m.write_u32(q+4,1);
        m.write_u32(q,0);m.write_u32(q+8,0x140478);m.write_u32(args,12345);
        bool rejected=false;try{(void)kx3::service_audio_worker(m,lookup);}catch(const std::runtime_error&){rejected=true;}
        check(rejected && !m.read_u32(q),"Missing PCM consumed a play");
        std::cout<<"{\"status\":\"passed\",\"source_id\":537002,\"volume\":80,\"ramp_ticks\":240,"
                 <<"\"delays\":[0,14],\"target_registers\":[[9600,800],[800,9600]],"
                 <<"\"duplicate_suppressed\":true,\"fade_stop\":true,\"blocking_stop_fields\":31,\"missing_pcm_rolled_back\":true}\n";
    }catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
