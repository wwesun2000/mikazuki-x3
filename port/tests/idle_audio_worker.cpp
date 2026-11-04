#include "../core/audio_worker.hpp"
#include "../core/guest_memory.hpp"
#include <algorithm>
#include <iostream>

namespace {
void require(bool ok) { if(!ok)throw std::runtime_error("Native idle audio check failed"); }
}
int main(){
    try{
        kx3::GuestMemory m;
        constexpr std::uint32_t q=0x23d3a0;
        m.write_u32(q,15);m.write_u32(q+4,1);
        m.write_u32(q+8+15*4,0x140aa8);m.write_u32(q+8,0x140aa8);
        m.write_u32(0x2389e8,0x32);m.write_u32(0x1e4c680,123);
        require(kx3::service_idle_audio_worker(m)==2 && m.read_u32(q)==1);
        require(m.read_u32(0x2389e8)==0 && m.read_u32(0x1e4c680)==0xffffffffu &&
                m.read_u32(0x238a08)==1 && m.read_u32(0x238a0c)==1);
        require(!kx3::service_idle_audio_worker(m));
        m.write_u32(q,15);m.write_u32(q+8,0x140478);
        auto rejected=[&]{
            const auto pre=m.bytes(0,m.size);
            const std::vector<std::uint8_t> copy(pre.begin(),pre.end());
            try{(void)kx3::service_idle_audio_worker(m);}
            catch(const std::runtime_error&){require(std::equal(copy.begin(),copy.end(),m.bytes(0,m.size).begin()));return;}
            throw std::runtime_error("Audio worker accepted unsupported state");
        };
        rejected(); // Failure after the first command must roll back the whole batch.
        m.write_u32(q+8,0x140aa8);m.write_u32(q+4,0);
        for(auto addr:{0x2389e0u,0x1e4c710u,0x2389f8u,0x1e4c22cu,0x1e6bfb0u+3*96,
                       q+280+48*15,q+284+48*15}){
            m.write_u32(addr,1);rejected();m.write_u32(addr,0);
        }
        m.write_u32(q+1048,1);
        require(!kx3::service_idle_audio_worker(m) && m.read_u32(q+1052)==1 && m.read_u32(q)==15);
        m.write_u32(q+1048,0);m.write_u32(0x2362a8,1);
        require(!kx3::service_idle_audio_worker(m) && m.read_u32(q)==15);
        std::cout<<"{\"status\":\"passed\",\"drained_wraparound\":2,\"negative_full_ram_checks\":8,\"pause_gates\":2}\n";
        return 0;
    }catch(const std::exception& err){std::cerr<<err.what()<<'\n';return 1;}
}
