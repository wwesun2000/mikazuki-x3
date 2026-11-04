#include "../core/guest_memory.hpp"
#include "../core/screen_projection.hpp"
#include <bit>
#include <fstream>
#include <iostream>
#include <iterator>

int main(int argc,char** argv){
    if(argc!=2)return 2;
    std::ifstream file(argv[1],std::ios::binary);
    std::vector<std::uint8_t> elf{std::istreambuf_iterator<char>(file),{}};
    if(elf.size()<0x237dc0-0xff000)return 3;
    kx3::GuestMemory m;
    m.write_bytes(0x211ef0,std::span(elf).subspan(0x211ef0-0xff000,16));
    m.write_bytes(0x237d5c,std::span(elf).subspan(0x237d5c-0xff000,0x60));
    char mode;std::uint32_t a,b;
    while(std::cin>>mode>>a>>b){
        const auto x=std::bit_cast<float>(a),y=std::bit_cast<float>(b);
        if(mode=='s'){std::cout<<kx3::screen_sector_for_y(m,x,y)<<'\n';continue;}
        const auto p=mode=='p'?kx3::screen_project_point(m,x):kx3::clip_screen_point(m,{x,y});
        std::cout<<std::bit_cast<std::uint32_t>(p[0])<<" "<<std::bit_cast<std::uint32_t>(p[1]);
        if(mode=='p')std::cout<<" "<<kx3::screen_project_sector(m,x);
        std::cout<<"\n";
    }
}
