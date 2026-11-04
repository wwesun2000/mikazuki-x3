#include "../core/choice_pipeline.hpp"
#include <cstdint>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

// Logical presentation consumer for an entry-only state differential. No GUI,
// render cadence, or downstream readback context execution is claimed.
struct ReadbackPresentation final : kx3::ChoiceServices {
    std::map<unsigned,bool> pointers;
    std::map<std::uint32_t,std::pair<std::uint32_t,std::uint32_t>> tasks;
    std::map<std::uint32_t,bool> pauses;
    std::array<std::uint32_t,3> primary{},secondary{};
    bool supports_source(std::uint32_t) const override{return false;}
    std::uint64_t call_source(kx3::GuestMemory&,std::uint32_t,std::span<const std::uint64_t>) override{
        throw std::runtime_error("Unrecovered readback source callback");
    }
    bool supports_effect(kx3::ChoiceEffectKind k) const override {
        using E=kx3::ChoiceEffectKind;
        return k==E::pointer_hide || k==E::font_palette || k==E::task_callbacks || k==E::task_pause;
    }
    bool glyph_animation_pending() const override{throw std::runtime_error("Entry-only probe cannot supply animation readiness");}
    void publish(const kx3::ChoiceUpdate& r) {
        using E=kx3::ChoiceEffectKind;
        for(const auto& e:r.pending_effects) {
            if(!supports_effect(e.kind))throw std::runtime_error("Unexpected presentation event");
            if(e.kind==E::pointer_hide)pointers[e.channel]=false;
            if(e.kind==E::font_palette){primary=e.rgb;secondary=e.secondary_rgb;}
            if(e.kind==E::task_callbacks)tasks[e.guest_task]={e.callback,e.secondary_callback};
            if(e.kind==E::task_pause)pauses[e.guest_task]=e.value!=0;
        }
    }
};
int main(int argc,char** argv){
    try{
        if(argc<7 || (argc-7)%2)throw std::runtime_error("entry a0 a1 a2 a3 t0 [output-address output-size]...");
        _setmode(_fileno(stdin),_O_BINARY);_setmode(_fileno(stdout),_O_BINARY);
        std::vector<std::uint8_t> bytes(kx3::GuestMemory::size);
        std::cin.read(reinterpret_cast<char*>(bytes.data()),bytes.size());
        if(std::cin.gcount()!=std::streamsize(bytes.size()))throw std::runtime_error("Expected32MiB input RAM");
        kx3::GuestMemory m;m.write_bytes(0,bytes);ReadbackPresentation backend;kx3::ChoiceUpdate update;
        std::uint64_t result=0;
        {
            kx3::GuestMemory::AccessBudget budget(m,8'000'000);kx3::GuestMemory::Transaction transaction(m);
            const auto entry=std::stoull(argv[1],nullptr,0);
            if(entry==0x134af0 || entry==0x134bd0)result=kx3::choice_readback_eligible(m)?1:0;
            else if(entry==0x1165d8) {
                update=kx3::choice_readback_begin_transactional(m,std::uint32_t(std::stoull(argv[2],nullptr,0)),
                    std::uint32_t(std::stoull(argv[3],nullptr,0)),std::stoull(argv[4],nullptr,0),
                    std::stoull(argv[5],nullptr,0),std::stoull(argv[6],nullptr,0),backend);
                result=update.handler_return;
            }else throw std::runtime_error("Entry outside recovered readback probe scope");
            transaction.commit();
        }
        backend.publish(update);
        for(unsigned i=0;i<8;++i)std::cout.put(char(result>>(i*8)));
        for(int i=7;i<argc;i+=2){
            const auto b=m.bytes(std::uint32_t(std::stoull(argv[i],nullptr,0)),std::stoull(argv[i+1],nullptr,0));
            std::cout.write(reinterpret_cast<const char*>(b.data()),b.size());
        }
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
