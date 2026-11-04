#include "../core/scene_registry.hpp"
#include <iostream>
#include <iterator>
#include <string>
#include <string_view>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static kx3::SceneRegistryResult check_provider(kx3::GuestMemory& memory,std::span<const std::uint8_t> spk,
        std::uint32_t registry,std::uint32_t base,std::uint32_t table,std::uint32_t capacity){
    constexpr std::uint32_t slot=0x235efc,provider=0x1000000;
    auto activate=[&](std::uint32_t allocation,std::span<const std::uint8_t> image){
        return kx3::activate_scene_provider(memory,allocation,registry,base,image,table,capacity);
    };
    memory.write_u32(provider,0x12345678);
    memory.write_u32(provider+28,0xfeedbeef);
    try{activate(provider,{});throw std::runtime_error("Empty SPK accepted");}
    catch(const std::invalid_argument&){}
    if(memory.read_u32(slot) || memory.read_u32(provider)!=0x12345678 || memory.read_u32(provider+28)!=0xfeedbeef)
        throw std::runtime_error("Failed load published a partial provider");
    const auto result=activate(provider,spk);
    if(memory.read_u32(slot)!=provider || memory.read_u32(provider)!=0x223770 || memory.read_u32(provider+4)!=result.registry)
        throw std::runtime_error("Original cold provider differs");
    // 11DAC0 returns an existing object without invoking its constructor again.
    memory.write_u32(provider,0x12345678);
    memory.write_u32(provider+28,0xfeedbeef);
    activate(0,spk);
    if(memory.read_u32(provider)!=0x12345678 || memory.read_u32(slot)!=provider)
        throw std::runtime_error("Live provider was replaced");
    for(unsigned off=8;off<32;off+=4)
        if(memory.read_u32(provider+off))throw std::runtime_error("Live provider retained stale scene state");
    return result;
}

int main(int argc, char** argv) {
    try {
        const bool verify_provider=argc==6 && std::string_view(argv[5])=="--provider";
        if (argc!=5 && !verify_provider) throw std::invalid_argument("Expected registry, file, reverse table, and capacity [--provider]");
#ifdef _WIN32
        _setmode(_fileno(stdin),_O_BINARY);
        _setmode(_fileno(stdout),_O_BINARY);
#endif
        const std::vector<std::uint8_t> spk(std::istreambuf_iterator<char>(std::cin),{});
        kx3::GuestMemory memory;
        const auto registry=std::stoul(argv[1]),base=std::stoul(argv[2]),table=std::stoul(argv[3]),capacity=std::stoul(argv[4]);
        const auto result=verify_provider?check_provider(memory,spk,registry,base,table,capacity):
            kx3::install_scene_registry(memory,registry,base,spk,table,capacity);
        for(auto bytes:{memory.bytes(result.registry,144),memory.bytes(result.file_base,spk.size()),
                        memory.bytes(result.cue_table,result.cue_count*4)}) {
            std::cout.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
        }
        if (!std::cout) throw std::runtime_error("Incomplete output");
        return 0;
    } catch(const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; }
}
