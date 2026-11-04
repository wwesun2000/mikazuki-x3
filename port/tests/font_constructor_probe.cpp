#include "../core/font_constructor.hpp"
#include "../core/guest_memory.hpp"
#include <fstream>
#include <iostream>
#include <string>

namespace {
using Bytes = std::vector<std::uint8_t>;
Bytes read_file(const char* path) {
    std::ifstream stream(path,std::ios::binary|std::ios::ate);
    const auto size = stream.tellg();
    if (!stream || size <= 0 || size > 2*1024*1024) throw std::runtime_error("Invalid original asset");
    Bytes bytes(static_cast<std::size_t>(size));
    stream.seekg(0);
    if (!stream.read(reinterpret_cast<char*>(bytes.data()),size)) throw std::runtime_error("Read failed");
    return bytes;
}
}

int main(int argc,char** argv) {
    try {
        if (argc != 5) throw std::runtime_error("Usage: font_constructor_probe original.elf source.fnt heap_fill output.bin");
        const auto elf = read_file(argv[1]), file = read_file(argv[2]);
        if (elf.size() != 1290132) throw std::runtime_error("Unexpected source executable");
        const auto fill = std::stoul(argv[3]);
        if (fill > 255) throw std::runtime_error("Invalid fill");
        kx3::GuestMemory m;
        m.write_bytes(0x100000,std::span(elf).subspan(0x1000,0x138648));
        m.write_bytes(0x600000,Bytes(0x40000,static_cast<std::uint8_t>(fill)));
        m.write_bytes(0x1e44200,Bytes(0x2f0,static_cast<std::uint8_t>(fill)));
        const Bytes before(m.bytes(0,m.size).begin(),m.bytes(0,m.size).end());
        bool rejected = false;
        try { (void)kx3::construct_font_object(m,0x600000,0x602000,0x900000,file); }
        catch (const std::runtime_error&) { rejected = true; }
        if (!rejected || !std::equal(before.begin(),before.end(),m.bytes(0,m.size).begin()))
            throw std::runtime_error("Partial allocation failure did not roll back");
        const auto result = kx3::construct_font_object(m,0x600000,0x640000,0x900000,file);
        if (result.font != 0x600000 || m.read_u32(0x238858) != result.font ||
            m.read_u32(0x23885c) != result.font) throw std::runtime_error("Font was not published");
        std::ofstream output(argv[4],std::ios::binary|std::ios::trunc);
        auto bytes = m.bytes(0,m.size);
        if (!output.write(reinterpret_cast<const char*>(bytes.data()),bytes.size())) throw std::runtime_error("Output failed");
        std::cout<<"{\"arena_used_end\":"<<result.arena_used_end<<",\"rollback_matches\":true}\n";
        return 0;
    } catch (const std::exception& e) {std::cerr<<e.what()<<'\n'; return 2;}
}
