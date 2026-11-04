#include "../core/sound_output_mode.hpp"
#include "../core/guest_memory.hpp"
#include <iostream>
int main(){
    using namespace kx3;
    try{
        GuestMemory m;m.write_u32(0x2389ec,1);
        enqueue_sound_output_mode(m,0);enqueue_sound_output_mode(m,1);
        if(m.read_u32(0x1e4c22c)!=2 || m.read_u32(0x1351000)!=0x1e4c240 ||
           m.read_u32(0x1351004)!=0x1e4c260 || m.read_u32(0x1e4c240)!=13 ||
           m.read_u32(0x1e4c264)!=1)throw std::runtime_error("Original 13 enqueue order mismatch");
        service_sound_packets(m);
        if(m.read_u32(0x1e4c22c) || m.read_u32(0x1e4c228)!=3 ||
           m.read_u32(0x2389b8)!=1 || m.read_u32(0x1e4c7b4)!=1 || m.read_u8(0x212cfc)!=1 ||
           m.read_u32(0x227800)!=0x0aa00008 || m.read_u8(0x227804)!=1 ||
           m.read_u32(0x1e4c240) || m.read_u32(0x1e4c260))throw std::runtime_error("Original mode dispatch mismatch");
        enqueue_sound_output_mode(m,0);service_sound_packets(m);
        if(m.read_u32(0x2389b8) || m.read_u32(0x1e4c7b4) || m.read_u8(0x212cfc) || m.read_u8(0x227804))
            throw std::runtime_error("Original mono request did not reach the native RPC buffer");
        for(unsigned i=0;i<16;++i)enqueue_sound_output_mode(m,i%2);
        bool full=false;
        try{enqueue_sound_output_mode(m,0);}catch(const std::runtime_error&){full=true;}
        if(!full || m.read_u32(0x1e4c22c)!=16)throw std::runtime_error("Sound queue did not preserve pending requests");
        service_sound_packets(m);
        if(m.read_u32(0x1e4c22c) || m.read_u32(0x2389b8)!=1)throw std::runtime_error("Full source command batch failed to drain");
        std::cout<<"{\"output_commands\":19,\"full_pool_retry\":true,\"passed\":true}\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}
}
