#include "../core/runtime.hpp"
#include "../core/media_command.hpp"
#include <array>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <vector>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace {
std::uint32_t read32() {
    std::uint32_t value=0;
    for(unsigned i=0;i<4;++i) {
        const int b=std::cin.get();
        if(b==EOF) throw std::runtime_error("Truncated native walk input");
        value|=std::uint32_t(std::uint8_t(b))<<(8*i);
    }
    return value;
}
std::string hex(std::uint32_t value) {
    std::ostringstream s; s<<"0x"<<std::hex<<std::setw(8)<<std::setfill('0')<<value; return s.str();
}
std::string quote(const std::string& str) {
    std::ostringstream s; s<<'"';
    for(unsigned char c:str) {
        if(c=='"'||c=='\\') s<<'\\'<<c;
        else if(c<32) s<<"\\u00"<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(c);
        else s<<c;
    }
    s<<'"'; return s.str();
}
}
int main() {
    try {
#ifdef _WIN32
        _setmode(_fileno(stdin),_O_BINARY);
#endif
        std::array<char,4> magic{}; std::cin.read(magic.data(),4);
        if(std::string(magic.data(),4)!="KX3W" || read32()!=1) throw std::runtime_error("Unknown native walk format");
        const auto manager=read32();
        const auto limit=read32();
        if(!manager || limit==0 || limit>10000) throw std::runtime_error("Invalid native walk parameters");
        std::vector<std::uint8_t> ram(kx3::GuestMemory::size);
        std::cin.read(reinterpret_cast<char*>(ram.data()),ram.size());
        if(!std::cin || std::cin.peek()!=EOF) throw std::runtime_error("Native walk requires exactly one complete 32 MiB RAM fixture");
        kx3::GuestMemory m; m.write_bytes(0,ram);
        for(std::uint32_t i=0;i<limit;++i) {
            const auto script=m.read_u32(manager+0x38), context=m.read_u32(manager+0x40);
            const auto vtable=m.read_u32(context);
            const auto method=m.read_u32(manager+0x2b4)?0x001126e0:m.read_u32(vtable+4);
            const auto cursor=m.read_u32(script+0xd8);
            const auto opcode=m.read_u8(cursor);
            // Keep one prior state in memory only to verify rollback exactly.
            std::copy(m.bytes(0,ram.size()).begin(),m.bytes(0,ram.size()).end(),ram.begin());
            std::cout<<"{\"step\":"<<i<<",\"context_vtable\":"<<quote(hex(vtable))
                     <<",\"method\":"<<quote(hex(method))<<",\"cursor\":"<<quote(hex(cursor))
                     <<",\"next_byte\":"<<unsigned(opcode);
            try {
                const auto result=kx3::step_script_atomic(m,manager);
                std::cout<<",\"status\":\"returned\",\"return_value\":"<<result
                         <<",\"cursor_after\":"<<quote(hex(m.read_u32(script+0xd8)))<<"}\n";
                if(result) return 0; // Original context yielded; not a new fake game frame.
            } catch(const std::exception& e) {
                const bool unchanged=std::equal(ram.begin(),ram.end(),m.bytes(0,ram.size()).begin());
                std::cout<<",\"status\":\"blocked\",\"error\":"<<quote(e.what())
                         <<",\"full_ram_rolled_back\":"<<(unchanged?"true":"false");
                if(const auto* media=dynamic_cast<const kx3::MissingMediaBackend*>(&e)) {
                    std::ostringstream token;
                    for(auto b:media->request.token_bytes) token<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(b);
                    std::cout<<",\"media_descriptor\":"<<quote(hex(media->request.descriptor))
                             <<",\"media_token_hex\":"<<quote(token.str());
                }
                std::cout<<"}\n";
                return unchanged?3:4;
            }
        }
        std::cout<<"{\"status\":\"step_limit\"}\n";
        return 5;
    } catch(const std::exception& e) {
        std::cerr<<e.what()<<'\n'; return 2;
    }
}
