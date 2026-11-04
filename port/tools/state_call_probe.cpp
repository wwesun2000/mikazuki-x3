#include "../core/recovered.hpp"
#include "../core/guest_memory.hpp"
#include <array>
#include <iostream>
#include <vector>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace {
std::uint64_t read(unsigned width) {
    std::uint64_t n=0;
    for(unsigned i=0;i<width;++i) {const int c=std::cin.get();if(c==EOF)throw std::runtime_error("Truncated state call");n|=std::uint64_t(std::uint8_t(c))<<(i*8);}
    return n;
}
void write(std::uint64_t n,unsigned width){for(unsigned i=0;i<width;++i)std::cout.put(char(std::uint8_t(n>>(i*8))));}
}
int main() {
    try {
#ifdef _WIN32
        _setmode(_fileno(stdin),_O_BINARY);_setmode(_fileno(stdout),_O_BINARY);
#endif
        std::array<char,4> magic{};std::cin.read(magic.data(),4);
        if(std::string(magic.data(),4)!="KX3C" || read(4)!=1)throw std::runtime_error("Unknown full-state call protocol");
        const auto entry=std::uint32_t(read(4)),self=std::uint32_t(read(4));
        const auto a1=read(8),a2=read(8),a3=read(8);
        const auto count=read(4);if(count>65536)throw std::runtime_error("Too many observations");
        std::vector<std::pair<std::uint32_t,std::uint32_t>> observed;
        kx3::GuestMemory m;
        for(std::size_t i=0;i<count;++i) {
            const auto address=std::uint32_t(read(4)),length=std::uint32_t(read(4));
            (void)m.bytes(address,length);observed.emplace_back(address,length);
        }
        std::vector<std::uint8_t> ram(m.size);
        std::cin.read(reinterpret_cast<char*>(ram.data()),ram.size());
        if(!std::cin || std::cin.peek()!=EOF)throw std::runtime_error("Expected one complete RAM fixture");
        m.write_bytes(0,ram);
        std::uint64_t result;
        {
            kx3::GuestMemory::AccessBudget budget(m,8'000'000);
            kx3::GuestMemory::Transaction transaction(m);
            result=kx3::invoke_recovered(m,entry,self,a1,a2,a3);
            transaction.commit();
        }
        std::cout.write("KX3E",4);write(1,4);write(result,8);
        for(const auto& [address,length]:observed) {
            const auto bytes=m.bytes(address,length);
            std::cout.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
        }
        if(!std::cout)throw std::runtime_error("Failed state-call output");
        return 0;
    } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 2;}
}
