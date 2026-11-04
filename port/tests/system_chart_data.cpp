#include "../core/system_charts.hpp"
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
namespace {
using u32=std::uint32_t;
std::vector<std::uint8_t> file(const std::filesystem::path& p){
    std::ifstream in(p,std::ios::binary|std::ios::ate);
    if(!in)throw std::runtime_error("Missing source file: "+p.string());
    std::vector<std::uint8_t> result(static_cast<std::size_t>(in.tellg()));in.seekg(0);
    if(!in.read(reinterpret_cast<char*>(result.data()),result.size()))throw std::runtime_error("Short source file");
    return result;
}
}
int main(int argc,char** argv){
    try{
        if(argc!=3)throw std::invalid_argument("Pass project root and original slot 7 RAM");
        const std::filesystem::path root=argv[1];
        kx3::GuestMemory original,live;
        original.write_bytes(0,file(argv[2]));
        const auto elf=file(root/"local/extracted/SLPM_664.52");
        live.write_bytes(0x100000,std::span(elf).subspan(0x1000,0x138648));
        const auto data=file(root/"local/assets/CHART/sn4g_tim.dat");
        constexpr u32 native_base=0x1330000;
        kx3::install_time_chart(live,native_base,128*1024,data);
        const auto observed_base=original.read_u32(0x2381b8);
        if(!std::ranges::equal(data,original.bytes(observed_base,data.size())))
            throw std::runtime_error("Original unmodified TIM differs from observed slot 7 payload");
        unsigned compared=0;
        auto verify=[&](u32 p,u32 q,bool relative){
            const auto a=live.read_u32(p),b=original.read_u32(q);
            if((relative?a-native_base:a)!=(relative?b-observed_base:b)){
                std::cerr<<"Mismatch at 0x"<<std::hex<<p<<", values "<<a<<' '<<b<<" bases "<<native_base<<' '<<observed_base<<'\n';
                throw std::runtime_error("Original chart loader table mismatch");
            }
            ++compared;
        };
        for(u32 p:{0x238960,0x238968,0x23896c,0x238974,0x23897c,0x238988,
                   0x238998,0x23899c,0x239e38+5*16})verify(p,p,false);
        for(u32 p:{0x238964,0x238970,0x238978,0x238980,0x238984,0x23898c,
                   0x238990,0x238994})verify(p,p,true);
        for(u32 i=0;i<live.read_u32(0x238968);++i)
            verify(live.read_u32(0x2381bc)+4*i,original.read_u32(0x2381bc)+4*i,true);
        for(u32 i=0;i<live.read_u32(0x238988);++i)verify(0x1e4bf28+i*4,0x1e4bf28+i*4,true);
        for(u32 i=0;i<4;++i)for(u32 p:{0x1e4bf40,0x1e4bf50,0x1e4bf60})
            verify(p+i*4,p+i*4,p!=0x1e4bf50);
        std::cout<<"{\"verified_original_chart_words\":"<<compared<<",\"time_slots\":"<<live.read_u32(0x238960)
                 <<",\"unlocks\":"<<live.read_u32(0x238974)<<",\"titles\":"<<live.read_u32(0x238968)<<"}\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}
}
