#include "../core/choice_pipeline.hpp"
#include <cstdint>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

struct NoExternal final : kx3::ChoiceServices {
    bool supports_source(std::uint32_t) const override{return false;}
    std::uint64_t call_source(kx3::GuestMemory&,std::uint32_t,std::span<const std::uint64_t>) override{
        throw std::runtime_error("Required external source callback unavailable");
    }
    bool supports_effect(kx3::ChoiceEffectKind) const override{return false;}
    bool glyph_animation_pending() const override{throw std::runtime_error("No renderer in transfer-only probe");}
};
int main(int argc,char** argv){
    try{
        if(argc<5 || (argc-5)%2)throw std::runtime_error("a0 a1 a2 a3 [output-address output-size]...");
        _setmode(_fileno(stdin),_O_BINARY);_setmode(_fileno(stdout),_O_BINARY);
        std::vector<std::uint8_t> bytes(kx3::GuestMemory::size);
        std::cin.read(reinterpret_cast<char*>(bytes.data()),bytes.size());
        if(std::cin.gcount()!=std::streamsize(bytes.size()))throw std::runtime_error("Expected32MiB input RAM");
        kx3::GuestMemory m;m.write_bytes(0,bytes);NoExternal services;
        {
            kx3::GuestMemory::AccessBudget budget(m,8'000'000);kx3::GuestMemory::Transaction transaction(m);
            kx3::choice_transfer_transactional(m,std::uint32_t(std::stoull(argv[1],nullptr,0)),
                std::stoull(argv[2],nullptr,0),std::uint32_t(std::stoull(argv[3],nullptr,0)),std::stoull(argv[4],nullptr,0),services);
            transaction.commit();
        }
        for(int i=5;i<argc;i+=2){
            const auto b=m.bytes(std::uint32_t(std::stoull(argv[i],nullptr,0)),std::stoull(argv[i+1],nullptr,0));
            std::cout.write(reinterpret_cast<const char*>(b.data()),b.size());
        }
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
