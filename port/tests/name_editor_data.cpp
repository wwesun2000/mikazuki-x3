#include "../core/guest_memory.hpp"
#include "../core/name_entry.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
namespace {
std::vector<std::uint8_t> file(const std::filesystem::path& p){
    std::ifstream in(p,std::ios::binary|std::ios::ate);if(!in)throw std::runtime_error("Missing test file");
    std::vector<std::uint8_t> data(static_cast<size_t>(in.tellg()));in.seekg(0);
    if(!in.read(reinterpret_cast<char*>(data.data()),data.size()))throw std::runtime_error("Short source read");
    return data;
}
}
int main(int argc,char** argv){
    try{
        if(argc!=3)throw std::invalid_argument("Pass project root and original slot 7 RAM");
        kx3::GuestMemory native,original;const std::filesystem::path root=argv[1];
        original.write_bytes(0,file(argv[2]));const auto elf=file(root/"local/extracted/SLPM_664.52");
        native.write_bytes(0x100000,std::span(elf).subspan(0x1000,0x138648));
        kx3::install_name_entry(native,0x300000,file(root/"local/assets/SCENARIO/namkan.txt"));
        const auto p=native.read_u32(0x235ed0),q=original.read_u32(0x235ed0);
        if(native.read_u32(p)!=original.read_u32(q)||native.read_u32(p+0x58)!=11 || original.read_u32(q+0x58)!=11)
            throw std::runtime_error("Original name editor vtable or group count mismatch");
        unsigned total=0;
        for(unsigned group=0;group<11;++group){
            const auto a=native.read_u32(p+0x5c)+group*8,b=original.read_u32(q+0x5c)+group*8;
            const auto n=native.read_u32(a);
            if(n!=original.read_u32(b))throw std::runtime_error("Original character page size mismatch");
            for(unsigned row=0;row<n;++row){
                // 11BE28 writes 15 U16 glyphs and 15 U8 flags. The final byte
                // of each 46-byte row is original allocator padding.
                const auto x=native.bytes(native.read_u32(a+4)+row*46,45);
                const auto y=original.bytes(original.read_u32(b+4)+row*46,45);
                if(!std::ranges::equal(x,y))throw std::runtime_error("Original name character/tag mismatch");
            }
            total+=n*15;
        }
        std::cout<<"{\"groups\":11,\"character_cells_and_tags_verified\":"<<total<<"}\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}
}
