#include "../core/script_image.hpp"
#include <fstream>
#include <iostream>
#include <iterator>

int main(int argc,char** argv) {
    try {
        if(argc!=3) throw std::runtime_error("Usage: script_index_probe original.sn4 index.bin");
        std::ifstream input(argv[1],std::ios::binary|std::ios::ate);
        if(!input || input.tellg()<0 || input.tellg()>8*1024*1024) throw std::runtime_error("Invalid bounded script input");
        input.seekg(0);
        std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(input)),{});
        kx3::GuestMemory memory;
        const auto index=kx3::load_script_index(memory,bytes,0x00400000,0x01000000);
        const auto original_marker=memory.read_u8(index.image+100);
        memory.write_u8(index.image+100,std::uint8_t(original_marker^0xff));
        std::vector<std::uint8_t> before(memory.bytes(0,memory.size).begin(),memory.bytes(0,memory.size).end());
        bool exhausted=false;
        try {(void)kx3::load_script_index(memory,bytes,0x00400000,index.end-1);}
        catch(const std::runtime_error& e) {exhausted=std::string(e.what()).find("arena exhausted")!=std::string::npos;}
        if(!exhausted || !std::equal(before.begin(),before.end(),memory.bytes(0,memory.size).begin()))
            throw std::runtime_error("Failed script-index allocation did not roll back complete RAM");
        memory.write_u8(index.image+100,original_marker);
        std::ofstream output(argv[2],std::ios::binary|std::ios::trunc);
        if(!output) throw std::runtime_error("Cannot create native script index evidence");
        auto write32=[&](std::uint32_t n){for(int i=0;i<4;++i)output.put(char(std::uint8_t(n>>(8*i))));};
        output.write("KX3L",4);write32(1);write32(index.block_count);write32(index.label_count);
        for(std::uint32_t b=0;b<index.block_count;++b) {
            const auto block=memory.read_u32(index.self+8+b*4);
            const auto code=memory.read_u32(block+0x430);
            write32(block-index.image);write32(code-block);
        }
        for(std::uint32_t id=0;id<index.label_count;++id) {
            const auto symbol=memory.read_u32(index.labels+id*4);
            write32(id);write32(symbol-index.image);write32(memory.read_u32(symbol+4));
        }
        if(!output) throw std::runtime_error("Failed native index output");
        std::cout<<"{\"blocks\":"<<index.block_count<<",\"labels\":"<<index.label_count
                 <<",\"guest_bytes_reserved\":"<<index.end-0x00400000<<",\"allocation_failure_rolled_back\":true}\n";
        return 0;
    } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 2;}
}
