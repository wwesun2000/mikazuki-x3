#include "sound_output_mode.hpp"
#include "guest_memory.hpp"
#include <array>
#include <bit>
namespace kx3 {
namespace {
using u32=std::uint32_t;
constexpr u32 queue=0x1e4c220,commands=0x1e4c240,marker=0x238244;
// Host allocation reserved for the 17 pointers requested by 153DE8.
constexpr u32 storage=0x1351000,owned=storage+0x80,signature=0x4b583133;
void prepare_queue(GuestMemory& m){
    // Original audio initialization creates this mutex with priority 12.
    if(!m.read_u32(0x2107c0) || m.read_u32(0x2107c0)==UINT32_MAX){
        m.write_u32(0x2107c0,storage+0x90);m.write_u32(0x2107c4,UINT32_MAX);
        m.write_u32(0x2107c8,0);m.write_u32(0x2107cc,12);
    }
    if(m.read_u32(owned)==signature)return;
    if(!m.read_u32(queue+16)){
        // Native single-session semaphores have unique guest-visible identities.
        m.write_u32(queue,storage+0x88);m.write_u32(queue+4,storage+0x8c);
        m.write_u32(queue+8,0);m.write_u32(queue+12,0);m.write_u32(queue+16,17);m.write_u32(queue+20,storage);
        for(u32 i=0;i<17;++i)m.write_u32(storage+i*4,0);
        for(u32 i=0;i<16;++i)m.write_u32(commands+i*32,0); // 1B00E8.
        m.write_u32(marker,1);
    }
    if(m.read_u32(queue+16)!=17 || !m.read_u32(queue+20))
        throw std::runtime_error("Invalid original sound command queue 0x00153de8");
    m.write_u32(owned,signature);
}
void push(GuestMemory& m,u32 packet){ // 154218, under the native session owner.
    const auto n=m.read_u32(queue+12),head=m.read_u32(queue+8);
    if(n>=17 || head>=17)throw std::runtime_error("1B06F8 requires an available original sound queue slot");
    m.write_u32(queue+12,n+1);m.write_u32(m.read_u32(queue+20)+4*((head+n)%17),packet);m.write_u32(0x238248,1);
}
void send_rpc(GuestMemory& m,u32 mode){
    m.write_u32(0x2389b8,mode); // 1B0F58.
    if(m.read_u32(0x2389ec)==1)m.write_u32(0x1e4c7a8+12,mode!=0); // 1B3C18 -> 1B3840.
    m.write_u8(0x212cfc,mode!=0); // 1D0648 -> 1D0D18.
    const auto pointer=m.read_u32(0x1e6ae20);
    // The original RPC payload uses an uncached alias of the static 227800
    // buffer. If the hardware service is new, bind its native alias here.
    if(!pointer)m.write_u32(0x1e6ae20,0x20227800);
    const auto packet=m.read_u32(0x1e6ae20)&0x1fffffffu;
    m.write_u32(packet,0x0aa00008);m.write_u8(packet+4,mode!=0);
}
}
u32 allocate_sound_packet(GuestMemory& m,u32 command){
    if(!m.transaction_active())throw std::logic_error("Sound packet production requires a guest transaction");
    prepare_queue(m);
    for(u32 i=0;i<16;++i){
        const auto packet=commands+i*32;
        if(m.read_u32(packet))continue;
        m.write_u32(packet,command);return packet;
    }
    throw std::runtime_error("1B0670 requires an available source sound command packet");
}
void submit_sound_packet(GuestMemory& m,u32 packet){
    if(!m.transaction_active() || packet<commands || packet>=commands+16*32 ||
       (packet-commands)%32 || !m.read_u32(packet))throw std::logic_error("Invalid source sound packet");
    push(m,packet);
}
void enqueue_sound_output_mode(GuestMemory& m,u32 enabled){
    if(!m.transaction_active()){
        GuestMemory::Transaction tx(m);enqueue_sound_output_mode(m,enabled);tx.commit();return;
    }
    const auto packet=allocate_sound_packet(m,13);m.write_u32(packet+4,enabled);submit_sound_packet(m,packet);
}
std::vector<SourceSoundEvent> service_sound_packets(GuestMemory& m){
    if(m.read_u32(owned)!=signature)return {};
    if(!m.transaction_active()){
        GuestMemory::Transaction tx(m);auto events=service_sound_packets(m);tx.commit();return events;
    }
    std::vector<SourceSoundEvent> events;
    if(m.read_u32(0x238248) && m.read_u32(queue+12)<17){
        push(m,marker);m.write_u32(0x238248,0); // Original 1B05A8 submits the frame marker.
    }
    while(m.read_u32(queue+12)){
        const auto head=m.read_u32(queue+8);
        if(head>=17 || m.read_u32(queue+12)>17)throw std::runtime_error("Invalid 154398 source sound queue");
        const auto p=m.read_u32(m.read_u32(queue+20)+head*4);
        if(p==marker && m.read_u32(p)==1){
            // 1B05F8 returns directly on an inactive device. Its live-device
            // tail is the retail 1B0CE0 JR RA; NOP.
        }else if(p>=commands && p<commands+16*32 && !(u32(p-commands)%32)){
            const auto cmd=m.read_u32(p);
            if(cmd==13)send_rpc(m,m.read_u32(p+4));
            else if(cmd==3 || cmd==10){
                SourceSoundEvent e;
                e.action=cmd==3?SoundAction::StopBgm:SoundAction::StopEffects;
                e.transition_ticks=m.read_u32(p+(cmd==3?24:12));
                if(cmd==3){
                    m.write_u32(0x238a0c,std::bit_cast<std::int32_t>(e.transition_ticks)<1);
                    m.write_u32(0x238a08,1); // 1B26B8 -> 1B40C8.
                }else{
                    m.write_u32(0x2389e0,0);m.write_u32(0x1e4c680,UINT32_MAX); // 1B1E88 -> 1B2158.
                }
                events.push_back(e);
            }else throw std::runtime_error("Unrecovered 1B0370 output queue packet");
            m.write_u32(p,0); // 1B0414 returns this packet to the pool.
        }else throw std::runtime_error("Invalid 1B0370 output queue pointer");
        m.write_u32(queue+8,(head+1)%17);m.write_u32(queue+12,m.read_u32(queue+12)-1);
    }
    return events;
}
}
