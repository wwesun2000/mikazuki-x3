#include "audio_worker.hpp"
#include "sound_parameters.hpp"
#include "sound_output_mode.hpp"
#include "guest_memory.hpp"
#include "source_libc.hpp"
#include <algorithm>
#include <bit>
#include <sstream>

namespace kx3 {
namespace {
using u32=std::uint32_t;
constexpr u32 ring=0x23d3a0; // Worker 0, source command pointers and arguments.

[[noreturn]] void unavailable(u32 address,const char* operation) {
    std::ostringstream s;
    s<<"Unrecovered audio path 0x"<<std::hex<<address<<" ("<<operation<<")";
    throw std::runtime_error(s.str());
}

void stop_silent_device(GuestMemory& m,u32 transition,u32 completion) {
    // 13FCE4 calls 1B0028: packet 3 stops BGM, then packet 10 stops SE.
    // The native silent-device adapter replaces the EE message queues, SIF
    // DMA and IOP mixer. Never consume a request belonging to a live device.
    if(transition || completion)unavailable(0x1b0028,"timed stop or completion");
    if(m.read_u32(0x1e4c22c) || m.read_u32(0x1e4c44c))unavailable(0x1b06f8,"pending PS2 device packets");
    if(m.read_u8(0x1e4c710) || m.read_u32(0x2389f8) || m.read_u32(0x238a04) ||
       m.read_u32(0x212d00) || m.read_u32(0x1e6bea8))unavailable(0x1b40c8,"active or transitioning BGM");
    if(m.read_u32(0x2389e0))unavailable(0x1b1e88,"active SE list");
    // 1D3568 can still find an allocated device voice after the higher-level
    // SE list is cleared. Check the full pool, including physical channels.
    for(u32 voice=1;voice<10;++voice){
        if(m.read_u32(0x1e6bfb0+96*voice))unavailable(0x1d2c48,"active device voice");
    }
    m.write_u32(0x2389e8,0); // 1B2590 and 1B0068 clear BGM request/name.
    m.write_u8(0x1e4c710,0);
    m.write_u32(0x2389e0,0); // 1B2158 always emits the active SE list terminator.
    m.write_u32(0x1e4c680,0xffffffffu);
    // Device worker dispatch 231CD0[3] -> 1B26B8 -> 1B40C8 (immediate).
    m.write_u32(0x212d00,0);m.write_u32(0x1e6bea8,0); // 1D14A4
    m.write_u32(0x238a0c,1);m.write_u32(0x238a08,1);
}

u32 drain(GuestMemory& m) {
    if(m.read_u32(ring+1048)){m.write_u32(ring+1052,1);return 0;} // 13F84C
    if(m.read_u32(0x2362a8))return 0; // 13F888 worker suspend gate
    auto head=m.read_u32(ring);
    const auto tail=m.read_u32(ring+4);
    if(head>=16 || tail>=16)throw std::runtime_error("Invalid original sound ring index");
    u32 count=0;
    while(head!=tail){
        const auto command=m.read_u32(ring+8+4*head);
        if(command!=0x140aa8)unavailable(command,"pending source worker command");
        const auto args=ring+280+48*head;
        stop_silent_device(m,m.read_u32(args),m.read_u32(args+4));
        head=(head+1)%16;m.write_u32(ring,head);++count; // 13F938 only after successful dispatch.
    }
    return count;
}
}

std::uint32_t service_idle_audio_worker(GuestMemory& m) {
    if(m.transaction_active())return drain(m);
    GuestMemory::Transaction tx(m);
    const auto count=drain(m);
    tx.commit();
    return count;
}

namespace {
constexpr u32 list_count=0x2389e0,list=0x1e4c680;
void remove_loop(GuestMemory& m,u32 id){
    const auto count=m.read_u32(list_count);
    if(count>8)throw std::runtime_error("Invalid loop sound count");
    for(u32 i=0;i<count;++i){
        if(m.read_u32(list+16*i)!=id)continue;
        for(u32 k=i+1;k<count;++k)for(u32 field=0;field<16;field+=4)
            m.write_u32(list+16*(k-1)+field,m.read_u32(list+16*k+field));
        m.write_u32(list+16*(count-1),0xffffffffu);m.write_u32(list_count,count-1);return;
    }
}

SourceSoundEvent plan_play(const SoundRecord& rec,u32 id,u32 volume,u32 transition,std::int32_t pan,bool mono){
    static constexpr int gains[][2]={{0,16},{1,15},{2,14},{4,14},{6,13},{8,13},{10,13},{11,12},
        {12,12},{12,11},{13,10},{13,8},{13,6},{14,4},{14,2},{15,1},{16,0}}; // SSDV IRX pantable
    const bool stereo=(rec.flags&0x80)!=0;
    if(!rec.channels || !rec.pitch || rec.pitch>4095 || (stereo && rec.channels!=2))
        throw std::runtime_error("Invalid source sound routing");
    const auto delays=stereo?std::array<std::uint8_t,2>{0,0}:rec.route_delays;
    if(delays[0]==255 || delays[1]==255)unavailable(0x1d2f34,"unsupported voice delay");
    const int index=source_pan_index(float(pan)*0.01f);
    const int reg=source_volume_register(rec.volume,float(volume)/100.0f,1.f);
    SourceSoundEvent event;
    event.id=id;event.transition_ticks=transition;event.loop=(rec.flags&0x10)!=0;
    event.volume=volume;event.pan=pan;
    event.mono=mono;
    const int key0=std::max(1,int(delays[0])),key1=std::max(1,int(delays[1]));
    const bool paired=!delays[0]&&!delays[1];
    for(unsigned i=0;i<2;++i){
        const int left=gains[index][1]/(!paired&&i==1?8:1);
        const int right=gains[index][0]/(!paired&&i==0?8:1);
        event.voices[i]={stereo?i:0u,u32((i?key1:key0)-std::min(key0,key1)),
                         float(reg*left/16)/16384.0f,float(reg*right/16)/16384.0f};
        if(mono){
            // SSDV.IRX F0C and 11A0 use 8*V/10 independently for each SPU voice.
            const auto level=float(8*reg/10)/16384.0f;
            event.voices[i].left_gain=event.voices[i].right_gain=level;
        }
    }
    return event;
}

void finish_sound_command(GuestMemory& m){ // 13F718, after a signalled device call returns.
    const auto count=m.read_u32(0x238730)-1;
    m.write_u32(0x238730,std::bit_cast<std::int32_t>(count)<0?0:count);
}
// 13F808 keeps the ring head until the producer's 1B0958 VBlank wait returns.
// Its signed loop count is the 32-bit ADDIU result from the producer.
constexpr u32 remaining=0x1351100;
bool wait_for_transition(GuestMemory& m,u32 duration){
    const u32 count=duration+1;
    if(std::bit_cast<std::int32_t>(count)<=0)return false;
    m.write_u32(remaining,count);return true;
}
u32 completion_flag_offset(u32 command){
    switch(command){
    case 0x140478:return 20;
    case 0x1405d8:case 0x140680:case 0x140728:return 12;
    case 0x140540:case 0x140a10:case 0x1408c0:return 8;
    case 0x1407d0:case 0x140988:case 0x140aa8:return 4;
    default:unavailable(0x13f808,"suspended sound command");
    }
}
void clear_effect_list(GuestMemory& m){ // 1B2158
    m.write_u32(list_count,0);m.write_u32(list,0xffffffffu);
}
void consume_sound_ring(GuestMemory& m,const SoundLookup& lookup,std::vector<SourceSoundEvent>& events){
    // Saved native equivalent of the sleeping 13F808 worker's 1B0958 loop
    // index. Each invocation represents one VBlank; the actual ring head,
    // wait counters, loop list and command arguments remain source fields.
    if(m.read_u32(ring+1048)){m.write_u32(ring+1052,1);return;}
    if(m.read_u32(0x2362a8))return;
    auto head=m.read_u32(ring);
    const auto tail=m.read_u32(ring+4);
    if(head>=16 || tail>=16)throw std::runtime_error("Invalid original sound ring index");
    while(head!=tail){
        const auto command=m.read_u32(ring+8+4*head),args=ring+280+48*head;
        const auto id=m.read_u32(args),arg1=m.read_u32(args+4);
        SourceSoundEvent event;
        if(const auto left=m.read_u32(remaining)){
            if(!m.read_u32(args+completion_flag_offset(command)))
                unavailable(0x13f808,"suspended command mismatch");
            m.write_u32(remaining,left-1);
            if(left>1)return;
            if(command==0x140540)remove_loop(m,id); // 1B2200 after 1B0958.
            if(command==0x1407d0 || command==0x140aa8)clear_effect_list(m);
            finish_sound_command(m);
        }else if(command==0x140478){
            const auto transition=m.read_u32(args+8);
            const bool signals=m.read_u32(args+20)!=0;
            if(id!=0xffffffffu){
                const auto* rec=lookup(id);
                if(!rec)throw std::runtime_error("SE_PLAY missing prepared original sound "+std::to_string(id));
                const auto count=m.read_u32(list_count);
                if(count>8)throw std::runtime_error("Invalid original active loop list");
                bool existing=false;
                if(rec->flags&0x10)for(u32 i=0;i<count;++i)existing|=m.read_u32(list+16*i)==id;
                if(!existing){
                    auto volume=arg1;
                    if(!transition){
                        for(auto i=(head+1)%16;i!=tail;i=(i+1)%16){
                            const u32 following=ring+280+48*i;
                            if(m.read_u32(ring+8+4*i)==0x1405d8 && m.read_u32(following)==id &&
                               m.read_u32(following+4)==0 && m.read_u32(following+8)!=0){volume=0;break;}
                        }
                    }
                    const auto pan=m.read_u32(args+12);
                    event=plan_play(*rec,id,volume,transition,std::bit_cast<std::int32_t>(pan),!m.read_u32(0x207c08));
                    if(event.loop){
                        auto n=count;
                        if(n==8){
                            SourceSoundEvent displaced;displaced.action=SoundAction::Stop;displaced.id=m.read_u32(list);
                            events.push_back(displaced);remove_loop(m,displaced.id);--n;
                        }
                        m.write_u32(list+16*n,id);m.write_u32(list+16*n+4,volume);m.write_u32(list+16*n+8,pan);
                        m.write_u32(list+16*(n+1),0xffffffffu);m.write_u32(list_count,n+1);
                    }else {m.write_u32(0x2389d8,id);m.write_u32(0x2389dc,0);}
                    events.push_back(event);
                    // 1B15F0 waits only after submitting a new, positive-duration start.
                    if(signals && std::bit_cast<std::int32_t>(transition)>0 && wait_for_transition(m,transition))return;
                }
            }
            if(signals)finish_sound_command(m);
        }else if(command==0x140728){
            const auto count=m.read_u32(list_count);
            if(count>8)throw std::runtime_error("Invalid loop table on pitch change");
            for(u32 i=0;i<count;++i)if(m.read_u32(list+16*i)==id){
                m.write_u32(list+16*i+12,arg1);break; // 1B19F0 -> 1B2308
            }
            event.action=SoundAction::Pitch;event.id=id;event.transition_ticks=m.read_u32(args+8);
            event.pitch_multiplier=source_pitch_multiplier(m,std::bit_cast<std::int32_t>(arg1));
            events.push_back(event);
            if(m.read_u32(args+12)){
                if(wait_for_transition(m,event.transition_ticks))return;
                finish_sound_command(m);
            }
        }else if(command==0x140680 || command==0x1405d8){
            const bool pan=command==0x140680;
            const auto count=m.read_u32(list_count);
            if(count>8)throw std::runtime_error("Invalid original loop table on pan");
            for(u32 i=0;i<count;++i)if(m.read_u32(list+16*i)==id){
                m.write_u32(list+16*i+(pan?8:4),arg1);break; // 1B1958/1B18C0 -> 1B2308
            }
            event.action=pan?SoundAction::Pan:SoundAction::Volume;event.id=id;
            event.pan=std::bit_cast<std::int32_t>(arg1);event.volume=arg1;event.mono=!m.read_u32(0x207c08);
            event.transition_ticks=m.read_u32(args+8);events.push_back(event);
            if(m.read_u32(args+12)){
                if(wait_for_transition(m,event.transition_ticks))return;
                finish_sound_command(m);
            }
        }else if(command==0x140540){
            event.action=SoundAction::Stop;event.id=id;event.transition_ticks=arg1;
            events.push_back(event); // 1B1858 submits SSDV command 6 before yielding.
            if(m.read_u32(args+8) && wait_for_transition(m,arg1))return;
            remove_loop(m,id);
            if(m.read_u32(args+8))finish_sound_command(m);
        }else if(command==0x140a10){
            m.write_u32(0x2389e8,id); // 1B2600 -> command packet 4.
            event.action=SoundAction::MusicVolume;event.music_volume=id;
            event.transition_ticks=arg1;events.push_back(event);
            if(m.read_u32(args+8)){
                if(wait_for_transition(m,arg1))return;
                finish_sound_command(m);
            }
        }else if(command==0x1408c0){
            const auto name=ring+72+13*head, live=0x1e4c710u;
            const auto length=source_strlen(m,name);
            if(!length || length>12)unavailable(0x1b2808,"music name");
            if(!m.read_u8(live) || source_strcmp(m,live,name)!=0) {
                event.action=SoundAction::PlayBgm;event.music_volume=id;event.transition_ticks=arg1;
                const auto bytes=m.bytes(name,length);event.music_name.assign(bytes.begin(),bytes.end());
                m.write_u32(0x2389e8,id);
                (void)source_strcpy(m,live,name);
                for(u32 i=u32(length)+1;i<16;++i)m.write_u8(live+i,0);
                (void)source_strcpy(m,0x1e4c898,name); // 1B42A8 stable request name.
                m.write_u32(0x2389fc,id);m.write_u32(0x238a00,arg1);
                m.write_u32(0x238a08,0);m.write_u32(0x238a0c,0);
                events.push_back(std::move(event));
                if(m.read_u32(args+8) && wait_for_transition(m,arg1))return;
            }
            if(m.read_u32(args+8))finish_sound_command(m);
        }else if(command==0x1407d0){
            event.action=SoundAction::StopEffects;event.transition_ticks=id;
            events.push_back(event);
            if(arg1 && wait_for_transition(m,id))return;
            clear_effect_list(m);
            if(arg1)finish_sound_command(m);
        }else if(command==0x140aa8 || command==0x140988){
            event.action=command==0x140aa8?SoundAction::StopAll:SoundAction::StopBgm;
            event.transition_ticks=id;
            m.write_u32(0x2389e8,0);m.write_u8(0x1e4c710,0);
            m.write_u32(0x238a0c,id?0:1);m.write_u32(0x238a08,1);
            events.push_back(event);
            if(arg1 && wait_for_transition(m,id))return;
            if(command==0x140aa8)clear_effect_list(m);
            if(arg1)finish_sound_command(m);
        }else unavailable(command,"pending source worker command");
        head=(head+1)%16;m.write_u32(ring,head);
    }
}
}
SourceSoundVoice source_pan_channel(const SoundRecord& r,u32 volume,std::int32_t pan,unsigned route,bool mono){
    return plan_play(r,0,volume,0,pan,mono).voices.at(route);
}
std::vector<SourceSoundEvent> service_audio_worker(GuestMemory& m,const SoundLookup& lookup){
    std::vector<SourceSoundEvent> events;
    if(m.transaction_active()){events=service_sound_packets(m);consume_sound_ring(m,lookup,events);}
    else{
        GuestMemory::Transaction tx(m);
        events=service_sound_packets(m);consume_sound_ring(m,lookup,events);tx.commit();
    }
    return events;
}
SourceSoundEvent system_sound(GuestMemory& m,u32 id,u32 volume,const SoundLookup& lookup){
    const auto* sound=lookup?lookup(id):nullptr;
    if(!sound || (sound->flags&0x10))throw std::runtime_error("System menu requires a prepared one-shot source sound");
    m.write_u32(0x2389d8,id);m.write_u32(0x2389dc,0); // 1B163C/40
    return plan_play(*sound,id,volume,0,0,!m.read_u32(0x207c08));
}
}
