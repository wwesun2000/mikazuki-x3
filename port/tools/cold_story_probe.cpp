#include "../platform/windows/project_game.hpp"
#include "../platform/windows/raster_loader.hpp"
#include "../core/staff_roll.hpp"
#include "../core/system_charts.hpp"
#include "../core/manager_input.hpp"
#include "../core/mystery_panel.hpp"
#include <set>
#include "../platform/windows/raster_loader.hpp"
#include "../platform/original_media_catalog.hpp"
#include "../platform/gradefilter_layer.hpp"
#include "../platform/expandblur_layer.hpp"
#include "../platform/screen_slide_layer.hpp"
#include "../platform/circlemask_layer.hpp"
#include "../core/choice_presentation.hpp"
#include "../core/name_entry.hpp"
#include <filesystem>
#include <algorithm>
#include <bit>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <numeric>
#include <iostream>
#include <stdexcept>

// Enter an actual wait on the unmodified cold route. Both physical controls
// and normal-dialogue mouse clicks eventually supply this same pad sample.
static void probe_choice(kx3::platform::windows::ProjectGame& game,std::string_view device,unsigned option) {
    const auto& m=game.memory();
    const auto owner=game.runtime().manager,choice=m.read_u32(owner+8),script=m.read_u32(owner+0x38);
    const auto count=m.read_u32(choice+4);
    if(!count || count>10 || option>=count)throw std::runtime_error("Requested option is outside the actual choice");
    const auto expected_selector=m.read_u32(choice+0x44+4*option);
    auto label=[&](std::uint32_t p){
        const auto bytes=m.bytes(p,64);
        const auto end=std::find(bytes.begin(),bytes.end(),0);
        if(end==bytes.end())throw std::runtime_error("Invalid source branch label");
        return std::string(bytes.begin(),end);
    };
    const auto expected=label(m.read_u32(choice+0x1c+4*option));
    auto advance=[&](const kx3::ChoiceInput& input){(void)game.advance(input);};
    kx3::ChoiceInput confirm;
    if(device=="mouse") {
        const auto font=m.read_u32(owner+0x3c),pool=m.read_u32(m.read_u32(font+8));
        const auto node=m.read_u32(pool+8)+56*m.read_u32(choice+0xc8+4*option);
        const auto hit=kx3::source_choice_at(m,owner,int(m.read_u32(node+12))+1,int(m.read_u32(node+16))+1);
        if(hit!=option){
            std::ostringstream detail;
            detail<<"Source option geometry failed mouse hit test; expected "<<option
                  <<" actual "<<(hit?std::to_string(*hit):"none");
            for(unsigned i=0;i<count;++i){
                const auto first=m.read_u32(choice+0xc8+4*i),last=m.read_u32(choice+0xf0+4*i);
                detail<<"; option "<<i<<" nodes "<<first<<".."<<last;
                for(auto n=first;n<=last && n<400;++n){
                    const auto p=m.read_u32(pool+8)+56*n;
                    detail<<" ["<<std::bit_cast<int>(m.read_u32(p+12))<<','
                          <<std::bit_cast<int>(m.read_u32(p+16))<<','
                          <<std::bit_cast<int>(m.read_u32(p+20))<<','
                          <<std::bit_cast<int>(m.read_u32(p+24))<<']';
                }
            }
            throw std::runtime_error(detail.str());
        }
        confirm.mouse_index=int(*hit);confirm.mouse_confirm=true;
    } else if(device=="keyboard") {
        for(unsigned n=0;n<count && m.read_u32(choice+0x168)!=option;++n) {
            advance(kx3::ChoiceInput{.held=0x40});advance({});
        }
        if(m.read_u32(choice+0x168)!=option)throw std::runtime_error("Source direction did not reach requested option");
        confirm.held=0x2000;
    } else throw std::invalid_argument("Unknown choice device");
    advance(confirm);
    if(m.read_u32(owner+0x40)!=m.read_u32(0x235f0c))throw std::runtime_error("Choice did not enter confirmation");
    for(unsigned ticks=0;ticks<200 && m.read_u32(owner+0x40)==m.read_u32(0x235f0c);++ticks)advance({});
    const auto id=m.read_u32(script+0xd4);
    const auto reached=label(m.read_u32(m.read_u32(script+0xcc)+4*id)+8);
    if(reached!=expected || m.read_u32(script+0xd0)!=expected_selector)
        throw std::runtime_error("Choice failed to reach the source option target");
    std::cout<<"{\"stage\":\"branch\",\"tick\":"<<game.logical_tick()<<",\"device\":"<<std::quoted(std::string(device))
             <<",\"option\":"<<option<<",\"selector\":"<<expected_selector<<",\"label\":"<<std::quoted(reached)<<"}\n";
}

static void accept_default_name(kx3::platform::windows::ProjectGame& game,std::uint64_t limit) {
    const auto manager=game.runtime().manager;
    auto view=[&]{return kx3::name_entry_view(game.memory(),manager);};
    const auto start=view();
    if(!start.open || start.confirming || start.draft_cp932.empty())
        throw std::runtime_error("Original name editor is not at its default draft");
    auto report=[&](const char* stage,unsigned held) {
        std::cout<<"{\"stage\":\""<<stage<<"\",\"tick\":"<<game.logical_tick()<<",\"held\":"<<held
                 <<",\"source_name_slot\":"<<start.slot<<",\"default_cp932_hex\":\"";
        constexpr std::string_view digits="0123456789abcdef";
        for(const unsigned char c:start.draft_cp932)std::cout<<digits[c>>4]<<digits[c&15];
        std::cout<<"\"}\n";
    };
    auto tap=[&](std::uint16_t key) {
        if(game.logical_tick()+3>limit)throw std::runtime_error("Frame budget exhausted during name entry");
        game.advance(kx3::ChoiceInput{});game.advance(kx3::ChoiceInput{.held=key});
        report("name-button",key);game.advance(kx3::ChoiceInput{});
    };
    report("name-entered",0);tap(0x1000); // Original triangle opens confirmation.
    auto v=view();
    if(!v.open || !v.confirming || v.confirm_focus!=1 || v.draft_cp932!=start.draft_cp932)
        throw std::runtime_error("Original name confirmation did not select No or changed the draft");
    tap(0x10);v=view();
    if(!v.open || !v.confirming || v.confirm_focus || v.draft_cp932!=start.draft_cp932)
        throw std::runtime_error("Original up input did not select Yes for the unchanged draft");
    tap(0x2000);
    if(view().open)throw std::runtime_error("Original name confirmation did not release the editor");
    report("name-returned",0);
}

// Exercise each original manual command on the four-card 14B2A0 panel.
// A supplied PC session was produced by --walk-checkpoint from the disc.
static void probe_actor(kx3::platform::windows::ProjectGame& game){
    using u32=std::uint32_t;
    const auto& m=game.memory();const auto owner=game.runtime().manager;
    const auto obj=m.read_u32(owner+28),sc=m.read_u32(owner+56);
    // Isolated compatibility cases. The playable session remains untouched.
    {
        kx3::GuestMemory copy;copy.write_bytes(0,m.bytes(0,m.size));
        const auto original=copy.read_u32(owner+0x2a0);
        kx3::restore_missing_choice_bootstrap(copy,owner,0x1350000,0x1350800);
        if(!original || copy.read_u32(owner+0x2a0)!=original)throw std::runtime_error("Existing format stack replaced");
        copy.write_u32(owner+0x2a0,0);copy.write_u32(0x135077c,0xfc1ca77e);
        kx3::restore_missing_choice_bootstrap(copy,owner,0x1350000,0x1350800);
        const auto replacement=copy.read_u32(owner+0x2a0);
        if(copy.read_u32(0x135077c)!=0xfc1ca77e || replacement!=0x1350780 || copy.read_u32(replacement)!=1 ||
           copy.read_u32(replacement+4) || copy.read_u32(replacement+8)!=12 || copy.read_u32(replacement+12)!=0x13507c0)
            throw std::runtime_error("Invalid restored source format stack");
        copy.write_u32(replacement+4,1);copy.write_u32(0x13507c0,0x9ec86ac4);
        kx3::restore_missing_choice_bootstrap(copy,owner,0x1350000,0x1350800);
        if(copy.read_u32(replacement+4)!=1 || copy.read_u32(0x13507c0)!=0x9ec86ac4)
            throw std::runtime_error("Active migrated format snapshot was not retained");
    }
    auto tap=[&](kx3::ChoiceInput action){game.advance(kx3::ChoiceInput{});game.advance(action);};
    auto log=[&](const char* stage){
        const auto v=game.actor_choice();
        std::cout<<"{\"stage\":\""<<stage<<"\",\"tick\":"<<game.logical_tick()<<",\"focus\":"<<v.focus
                 <<",\"accepting\":"<<int(v.accepting)<<",\"opacity\":"<<v.opacity<<",\"selector\":"<<m.read_u32(sc+0xd0)
                 <<",\"label\":"<<m.read_u32(sc+0xd4)<<",\"chosen\":"<<m.read_u32(obj+4)<<"}\n";
    };
    for(u32 i=0;!game.actor_choice().open && i<30000;++i){
        const auto ctx=m.read_u32(owner+64);
        const bool wait=ctx==m.read_u32(0x235f34) || ctx==m.read_u32(0x235f38);
        game.advance(kx3::ChoiceInput{.held=std::uint16_t(wait && !(m.read_u16(0x1e41c68)&0x2000)?0x2000:0)});
    }
    if(!game.actor_choice().open)throw std::runtime_error("Cold actor panel did not open");
    log("entered");
    for(u32 i=0;!game.actor_choice().accepting && i<32;++i)game.advance(kx3::ChoiceInput{});
    const auto start=game.actor_choice();
    if(!start.accepting || start.focus>=4)throw std::runtime_error("14B2A0 did not finish its source fade");
    log("ready");
    for(u32 i=0;i<4;++i){
        tap({.held=0x20});
        const auto v=game.actor_choice();
        if(v.focus!=(start.focus+i+1)%4)throw std::runtime_error("Actor D-pad focus did not wrap");
        log("right");
    }
    tap({.held=0x4000});
    if(!game.actor_choice().accepting)throw std::runtime_error("Source cancel unexpectedly transferred");
    for(u32 i=0;i<4;++i)if(!start.portrait[i]){
        tap({.actor_index=int(i),.actor_confirm=true});
        if(game.actor_choice().focus!=i || !game.actor_choice().accepting)
            throw std::runtime_error("Locked actor click unexpectedly transferred");
        log("locked");break;
    }
    auto active=std::find_if(start.portrait.begin(),start.portrait.end(),[](auto x){return x!=0;});
    if(active==start.portrait.end())throw std::runtime_error("No available original actor");
    const auto index=u32(active-start.portrait.begin());
    const auto target=m.read_u32(obj+12+8*index),name=m.read_u32(obj+16+8*index);
    auto label=[&](u32 ptr){
        const auto v=m.bytes(ptr,64);const auto end=std::find(v.begin(),v.end(),0);
        if(end==v.end())throw std::runtime_error("Truncated actor label");return std::string(v.begin(),end);
    };
    const auto expected=label(name);
    tap({.actor_index=int(index),.actor_confirm=true});log("confirmed");
    if(game.actor_choice().accepting || m.read_u32(obj+4)!=index)throw std::runtime_error("Source actor confirm rejected");
    for(u32 i=0;!m.read_u32(obj) && i<65;++i)game.advance(kx3::ChoiceInput{});
    if(!m.read_u32(obj) || !m.read_u32(obj+80))throw std::runtime_error("Original hero panel did not signal its owner");
    {
        // Snapshot the immediate source return boundary. A normal game tick
        // executes further script instructions after 120900 returns zero.
        kx3::GuestMemory copy;copy.write_bytes(0,m.bytes(0,m.size));
        kx3::GuestMemory::Transaction tx(copy);
        if(kx3::invoke_recovered(copy,0x119b60,obj)!=1 || copy.read_u32(obj+80) ||
           copy.read_u32(owner+64)!=copy.read_u32(obj+8) || copy.read_u32(sc+0xd0)!=target ||
           copy.read_u32(sc+0xd4)!=kx3::invoke_recovered(copy,0x10fa88,sc,target,name))
            throw std::runtime_error("119B60 failed to transfer to the source actor label");
    }
    std::cout<<"{\"matched_label\":"<<std::quoted(expected)<<",\"selector\":"<<target<<"}\n";
    game.advance(kx3::ChoiceInput{});
    if(m.read_u32(obj+80))throw std::runtime_error("Normal hero return frame did not release 119A18");
    const auto reached=label(m.read_u32(m.read_u32(sc+0xcc)+4*m.read_u32(sc+0xd4))+8);
    log("returned");std::cout<<"{\"continued_label\":"<<std::quoted(reached)<<"}\n";
}

// Observe the original callback in a cold session without writing guest RAM.
// The midpoint's two raw 640x448 RGBA8 images are sufficient for a GS replay.
struct ExpandBandTrace {
    std::filesystem::path directory;
    std::uint32_t previous_task=0;
    bool captured=false,was_done=false;
    std::uint64_t last_tick=UINT64_MAX;
    void observe(const kx3::platform::windows::ProjectGame& game){
        if(directory.empty() || last_tick==game.logical_tick())return;
        last_tick=game.logical_tick();
        const auto& m=game.memory();
        const auto pool=m.read_u32(0x2388bc);
        std::uint32_t task=0;
        for(unsigned i=13;pool && i<23;++i){
            const auto p=pool+48*i;
            if(m.read_u32(p) && m.read_u32(p+20)==0x184760){task=p;break;}
        }
        if(!task){
            if(previous_task)std::cout<<"{\"stage\":\"expandband-released\",\"tick\":"<<last_tick<<"}\n";
            previous_task=0;return;
        }
        const auto data=m.read_u32(task+44),height=m.read_u32(data+4),done=m.read_u32(task+16);
        const bool created=previous_task!=task;
        if(created){captured=false;was_done=false;}
        previous_task=task;
        const bool midpoint=!captured && std::bit_cast<float>(height)<=std::bit_cast<float>(m.read_u32(0x237644))/2;
        std::cout<<"{\"stage\":\"expandband\",\"tick\":"<<last_tick<<",\"task\":"<<task
                 <<",\"height_bits\":"<<height<<",\"step_bits\":"<<m.read_u32(data+8)
                 <<",\"interval\":"<<m.read_u32(data)<<",\"done\":"<<done;
        if(created || midpoint || (done && !was_done)){
            const auto base=game.images().current_frame(),output=game.scene_frame();
            if(!base || !output)throw std::runtime_error("Cold expandband has no scene pixels");
            using kx3::platform::windows::source_bytes_sha256;
            std::cout<<",\"background_sha256\":"<<std::quoted(source_bytes_sha256(base->rgba))
                     <<",\"scene_sha256\":"<<std::quoted(source_bytes_sha256(output->rgba));
            if(midpoint){
                std::filesystem::create_directories(directory);
                for(const auto& [suffix,image]:{std::pair{"-background.rgba",base},std::pair{"-scene.rgba",output}}){
                    std::ofstream file(directory/(std::to_string(last_tick)+suffix),std::ios::binary);
                    file.exceptions(std::ios::failbit|std::ios::badbit);
                    file.write(reinterpret_cast<const char*>(image->rgba.data()),image->rgba.size());
                }
                captured=true;
            }
        }
        std::cout<<"}\n";was_done=done!=0;
    }
};

static int probe_wait(const std::filesystem::path& root,std::string_view scenario,unsigned duration,bool walk,
                      bool accept_names=false,std::string_view choice_device={},std::vector<unsigned> route={},
                      bool keep_walking=false,const std::filesystem::path& save_at_limit={},const std::filesystem::path& trace_dir={},
                      const std::filesystem::path& save_at_choice={},const std::filesystem::path& from={},
                      std::optional<unsigned> until_ending={},const std::filesystem::path& witness_store={}) {
    if(!duration || duration>100000)throw std::invalid_argument("Invalid wait probe budget");
    using kx3::platform::windows::ProjectGame;
    if(!from.empty() && std::filesystem::exists(save_at_limit) && std::filesystem::equivalent(from,save_at_limit))
        throw std::invalid_argument("Input checkpoint and route output must differ");
    auto session=from.empty()?std::make_unique<ProjectGame>(root,scenario,
        save_at_limit.empty() && trace_dir.empty() && save_at_choice.empty()?std::nullopt:std::optional<std::uint32_t>(4357)):
        ProjectGame::load(root,std::string(scenario),from);
    auto& game=*session;
    if(!witness_store.empty()){
        if(save_at_limit.empty())throw std::invalid_argument("Witness runs require a separate output checkpoint");
        std::filesystem::create_directories(witness_store);
        game.set_system_record_file(witness_store/(std::string(scenario)+"-system.dat"));
    }
    const auto limit=game.logical_tick()+duration;
    if(limit<game.logical_tick())throw std::invalid_argument("Wait probe tick overflow");
    ExpandBandTrace trace{trace_dir};
    const auto& m=game.memory();
    const auto owner=game.runtime().manager,script=m.read_u32(owner+0x38);
    std::vector<std::uint8_t> initial_bits;
    if(until_ending){
        const auto entries=kx3::ending_list_entries(m);
        if(*until_ending>=entries.size() || entries[*until_ending].reached)
            throw std::invalid_argument("Ending probe requires a locked original list entry");
        const auto bytes=m.bytes(0x1e4bf08,(entries.size()+7)/8);
        initial_bits.assign(bytes.begin(),bytes.end());
    }
    auto context=[&] { return m.read_u32(owner+0x40); };
    auto cursor=[&] { return m.read_u32(script+0xd8); };
    unsigned confirmed=0,choices=0;
    auto report=[&](std::string_view stage,std::uint16_t buttons=0) {
        std::cout<<"{\"stage\":"<<std::quoted(std::string(stage))<<",\"tick\":"<<game.logical_tick()
                 <<",\"context_vtable\":"<<m.read_u32(context())<<",\"cursor\":"<<cursor()
                 <<",\"selector\":"<<m.read_u32(script+0xd0)<<",\"label\":"<<m.read_u32(script+0xd4)
                 <<",\"held\":"<<buttons<<",\"accepted_waits\":"<<confirmed
                 <<",\"accepted_choices\":"<<choices<<",\"system_record_bytes\":"<<game.last_system_record().size()
                 <<",\"visible_glyphs\":"<<game.visible_text_events().size()
                 <<",\"image\":"<<game.images().current_generation()<<"}\n";
    };
    auto choose=[&]{
        report("choice");
        if(!witness_store.empty()){
            const auto choice=m.read_u32(owner+8),count=m.read_u32(choice+4);
            if(!count || count>10)throw std::runtime_error("Invalid live witness menu");
            std::cout<<"{\"stage\":\"witness-menu\",\"tick\":"<<game.logical_tick()<<",\"selector\":"
                     <<m.read_u32(script+0xd0)<<",\"offset\":"<<cursor()-m.read_u32(script+4)
                     <<",\"ram_sha256\":"<<std::quoted(kx3::platform::windows::source_bytes_sha256(m.bytes(0,m.size)))
                     <<",\"options\":[";
            for(unsigned i=0;i<count;++i){
                const auto bytes=m.bytes(m.read_u32(choice+0x1c+4*i),64);
                const auto end=std::find(bytes.begin(),bytes.end(),0);
                if(end==bytes.end())throw std::runtime_error("Invalid live witness label");
                if(i)std::cout<<',';
                std::cout<<"{\"index\":"<<i<<",\"selector\":"<<m.read_u32(choice+0x44+4*i)
                         <<",\"label\":"<<std::quoted(std::string(bytes.begin(),end))<<'}';
            }
            std::cout<<"]}\n";
        }
        if(!save_at_choice.empty()){game.save(save_at_choice);return false;}
        if(choices>=route.size()){
            if(until_ending)throw std::runtime_error("Route needs another choice before the expected ending");
            if(!witness_store.empty())game.save(save_at_limit);
            return false;
        }
        probe_choice(game,choice_device,route[choices++]);
        return keep_walking;
    };
    try {
        if(!from.empty())report("resumed-checkpoint");
        while(true) {
            if(until_ending){
                const auto bits=m.bytes(0x1e4bf08,initial_bits.size());
                if(!std::equal(bits.begin(),bits.end(),initial_bits.begin())){
                    initial_bits[*until_ending/8]|=std::uint8_t(1u<<(*until_ending%8));
                    if(!std::equal(bits.begin(),bits.end(),initial_bits.begin()))
                        throw std::runtime_error("A different ending was registered");
                    report("source-ending-registered");
                    if(!save_at_limit.empty())game.save(save_at_limit);
                    return 0;
                }
            }
            if(game.logical_tick()>=limit)break;
            trace.observe(game);
            if(walk && game.actor_choice().open){
                report("actor-selection");
                if(choices>=route.size()){
                    if(until_ending)throw std::runtime_error("Route needs an actor choice before the expected ending");
                    if(!witness_store.empty())game.save(save_at_limit);
                    return 0;
                }
                const auto index=route[choices++];
                auto step=[&](kx3::ChoiceInput buttons){
                    if(game.logical_tick()>=limit)throw std::runtime_error("Frame limit during actor selection");
                    game.advance(buttons);
                };
                while(!game.actor_choice().accepting)step({});
                if(index>=4 || !game.actor_choice().portrait[index])
                    throw std::runtime_error("Requested actor is locked in this original route");
                if(choice_device=="keyboard"){
                    while(game.actor_choice().focus!=index){step({.held=0x20});step({});}
                    step({.held=0x2000});
                }else if(choice_device=="mouse")step({.actor_index=int(index),.actor_confirm=true});
                else throw std::invalid_argument("Unknown actor choice device");
                const auto object=m.read_u32(owner+0x1c);
                if(m.read_u32(object+4)!=index)throw std::runtime_error("Actor route confirmation failed");
                while(m.read_u32(object+80))step({});
                report("actor-return");if(!keep_walking)return 0;
                continue;
            }
            if(walk && kx3::name_entry_view(m,owner).open){
                if(!accept_names){
                    report("name-entry");
                    if(until_ending)throw std::runtime_error("Route needs a name before the expected ending");
                    return 0;
                }
                accept_default_name(game,limit);continue;
            }
            game.advance(kx3::ChoiceInput{});
            trace.observe(game);
            const auto wait=context();
            // 7C -> 12D960/11A3D0 arms a label during a repeating scene.
            // 113094..1130CC accepts Circle in the default context. The
            // route driver presses the button; 11A470 performs the transfer.
            if(until_ending && kx3::alternate_label_armed(m,owner)){
                const auto alternate=m.read_u32(owner+0x2c);
                report("alternate-label-confirm");
                if(game.logical_tick()>=limit)break;
                game.advance(kx3::ChoiceInput{.held=0x2000});
                if(m.read_u32(alternate))throw std::runtime_error("Original alternate-label action did not accept Circle");
                ++confirmed;report("alternate-label-accepted",0x2000);
                continue;
            }
            if(walk && wait==m.read_u32(0x235f04)) {
                if(!choose())return 0;
                continue;
            }
            // 51 FFFFFFFF uses the default context and the interruptible
            // timer at manager+2E8. 113818 tests the original 2100 pad edge
            // before clearing its +4 counter. Ending titles use this wait.
            // Finite delays and non-interruptible timers remain untouched.
            if(walk && wait==m.read_u32(0x235f3c) && m.read_u32(owner+0x2e8) &&
               m.read_u32(owner+0x2ec)==UINT32_MAX) {
                report("interruptible-wait");
                if(game.logical_tick()>=limit)break;
                game.advance(kx3::ChoiceInput{.held=0x2000});
                if(m.read_u32(owner+0x2ec)==UINT32_MAX)
                    throw std::runtime_error("Original circle edge failed to release interruptible timer");
                ++confirmed;report("timer-confirmed",0x2000);
                continue;
            }
            if(wait!=m.read_u32(0x235f34) && wait!=m.read_u32(0x235f38))continue;
            report("entered");
            const auto before=cursor();
            if(!walk) {
                for(const std::uint16_t buttons:{0u,0u,0x20u,0u}) {
                    game.advance(kx3::ChoiceInput{.held=buttons});
                    if(context()!=wait || cursor()!=before)throw std::runtime_error("Unexpected advance without confirmation");
                }
                report("held");
            }
            if(game.logical_tick()>=limit)break;
            game.advance(kx3::ChoiceInput{.held=0x2000});
            if(context()==wait && cursor()==before)throw std::runtime_error("Original circle edge failed to release wait");
            ++confirmed;report("confirmed",0x2000);
            if(!walk)return 0;
            if(context()==m.read_u32(0x235f04)) {
                if(!choose())return 0;
            }
            // The next iteration starts with a released pad. No input is sent
            // in choice, preview, finite timer, menu, fade, or other contexts.
        }
        if(walk){
            if(until_ending)throw std::runtime_error("Ending was not registered before the probe limit");
            if(!save_at_limit.empty()){
                if(game.logical_tick()!=limit)throw std::runtime_error("Requested frame falls inside an input sequence");
                game.save(save_at_limit);
            }
            report("frame-limit");return 0;
        }
        throw std::runtime_error("Wait test exceeded frame budget");
    } catch(const std::exception& error) {
        std::cerr<<error.what()<<std::endl;
        report("stopped");return 3;
    }
}

int main(int argc,char** argv) {
    try {
        if(argc>=7 && std::string_view(argv[3])=="--card-replay"){
            using namespace kx3;
            auto game=platform::windows::ProjectGame::load(argv[1],argv[2],argv[5]);
            const auto ticks=std::stoul(argv[4]);if(ticks>5000)throw std::invalid_argument("Invalid card replay duration");
            const std::filesystem::path dir=argv[6];std::filesystem::create_directories(dir);
            game->set_system_record_file(dir/(std::string(argv[2])+"-system.bin"));
            std::map<unsigned,std::uint16_t> inputs;
            for(int i=7;i<argc;++i){
                const std::string token=argv[i];const auto split=token.find(':');
                if(split==std::string::npos)throw std::invalid_argument("Card input requires relative-tick:hex-pad");
                const auto buttons=std::stoul(token.substr(split+1),nullptr,16);
                if(buttons>65535 || !inputs.emplace(std::stoul(token.substr(0,split)),buttons).second)
                    throw std::invalid_argument("Invalid or duplicate card input");
            }
            const auto& m=game->memory();std::array<std::uint32_t,17> previous{};
            for(unsigned i=0;i<=ticks;++i){
                const auto buttons=inputs.contains(i)?inputs.at(i):0;
                const std::array state{m.read_u32(0x2388e8),m.read_u32(0x2380d0),m.read_u32(0x238058),
                    m.read_u32(0x238940),m.read_u32(0x238944),m.read_u32(0x238948),m.read_u32(0x23894c),
                    m.read_u32(0x239f40),m.read_u32(0x239f44),m.read_u32(0x239f48),m.read_u32(0x239f4c),
                    m.read_u32(0x239f50),m.read_u32(0x235b5c),m.read_u32(0x235b50),m.read_u32(0x235b54),
                    m.read_u32(0x2388cc),m.read_u32(0x23813c)};
                if(!i || buttons || state!=previous || i==ticks){
                    std::cout<<"{\"relative\":"<<i<<",\"tick\":"<<game->logical_tick()<<",\"pad\":"<<buttons<<",\"state\":[";
                    for(unsigned k=0;k<state.size();++k)std::cout<<(k?",":"")<<state[k];
                    std::cout<<"]}\n";previous=state;
                }
                if(i<ticks)game->advance(ChoiceInput{.held=std::uint16_t(buttons)});
            }
            game->save(dir/"replay.kx3save");return 0;
        }
        if(argc==7 && std::string_view(argv[3])=="--circle-boundary"){
            using namespace kx3;
            auto game=platform::windows::ProjectGame::load(argv[1],argv[2],argv[5]);
            const auto limit=std::stoul(argv[4]);
            if(limit>2000)throw std::invalid_argument("Unbounded circle replay");
            const std::filesystem::path out=argv[6];std::filesystem::create_directories(out);
            unsigned seen=0;bool rendered=false;
            for(unsigned n=0;n<limit;++n){
                game->advance({});
                const auto& m=game->memory();const auto pool=m.read_u32(0x2388bc);
                std::uint32_t task=0;
                for(unsigned i=0;i<10;++i){
                    auto p=pool+48*i;
                    if(m.read_u32(p) && m.read_u32(p+24)==0x193cb8){task=p;break;}
                }
                if(!task){
                    if(seen){std::cout<<"{\"released_tick\":"<<game->logical_tick()<<"}\n";return rendered?0:3;}
                    continue;
                }
                ++seen;
                const auto data=m.read_u32(task+44);
                std::cout<<"{\"tick\":"<<game->logical_tick()<<",\"task\":"<<task<<",\"mode\":"<<m.read_u32(data)
                         <<",\"radius_bits\":"<<m.read_u32(data+12)<<",\"remaining\":"<<m.read_u32(data+24)
                         <<",\"suspended_draw\":"<<m.read_u32(task+40);
                if(!m.read_u32(task+40)){
                    const auto frame=game->scene_frame();
                    if(!frame)throw std::runtime_error("Missing cold circle image");
                    rendered=true;
                    std::cout<<",\"scene_sha256\":"<<std::quoted(platform::windows::source_bytes_sha256(frame->rgba));
                    if(m.read_u32(data+24)==(m.read_u32(data)==8?30u:15u)){
                        const auto base=game->images().current_frame();
                        auto dump=[&](const char* name,std::span<const std::uint8_t> bytes){
                            std::ofstream f(out/name,std::ios::binary);f.exceptions(std::ios::badbit|std::ios::failbit);
                            f.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());
                        };
                        dump("current.rgba",base->rgba);dump("composed.rgba",frame->rgba);
                        for(unsigned i=0;i<2;++i)dump(i?"saved-odd.rgba":"saved-even.rgba",
                            m.bytes(m.read_u32(0x236114+4*i),640*224*4));
                    }
                }
                std::cout<<"}\n";
            }
            throw std::runtime_error("Circle boundary did not enter and release within the supplied interval");
        }
        const bool circle=argc>=3 && std::string_view(argv[2])=="--circle-mask";
        const bool incoming=argc>=3 && std::string_view(argv[2])=="--screen-incoming";
        const bool outgoing=argc>=3 && std::string_view(argv[2])=="--screen-outgoing";
        if(((argc==6 || argc==9) && (std::string_view(argv[2])=="--screen-slide" || incoming || outgoing)) || (circle && argc>=9)){
            using namespace kx3;
            const auto root=std::filesystem::path(argv[1]);
            GuestMemory m;
            const auto elf=platform::windows::read_disc_resource(root,"SLPM_664.52",
                "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160",1290132);
            m.write_bytes(0x100000,std::span(elf).subspan(0x1000,0x138648));
            m.write_u32(0x2388bc,0x320000);m.write_u32(0x235e40,0x330000);
            int arg=3;
            std::vector<std::uint32_t> args(circle?5:2);
            for(auto& value:args)value=std::uint32_t(std::stol(argv[arg++]));
            const auto ticks=std::stoul(argv[arg++]);
            if(ticks>10000)throw std::invalid_argument("Invalid transition duration");
            std::vector<std::uint8_t> texture;
            if(circle){
                texture=platform::windows::read_disc_resource(root,"EFFECT/smask.ctf",
                    "de880fb6ef343ed2e97358ee8416e6450a057996d954e15b0474693397c2ab12",8384);
                m.write_bytes(0x23a480,std::span(texture).first(128));
            }
            auto task=circle?create_circlemask(m,0x1000200,args):create_screen_slide(m,0x1000200,args,outgoing?0x18a710:incoming?0x18aad8:0x18b040);
            for(unsigned i=0;i<ticks && !m.read_u32(task+4);++i){
                if(circle)update_circlemask(m,task);else update_screen_slide(m,task);
            }
            const auto data=m.read_u32(task+44);
            if(circle && arg+2<=argc && std::string_view(argv[arg])=="--diameter"){
                const float radius=std::stof(argv[arg+1])*0.5f;arg+=2;
                if(radius<=0 || radius>2048)throw std::invalid_argument("Invalid probe radius");
                m.write_u32(data+12,std::bit_cast<std::uint32_t>(radius));
                for(unsigned axis=0;axis<2;++axis)m.write_u32(data+32+4*axis,
                    std::bit_cast<std::uint32_t>(float(std::int32_t(args[1+axis]))-radius));
            }
            if(argc!=arg && argc!=arg+3)throw std::invalid_argument("Unexpected transition fixture arguments");
            const auto passes=circle?draw_circlemask(m,task):CircleDraw{};
            const auto sprites=circle?SlideDraw{passes.at(1).xy,{}}:draw_screen_slide(m,task);
            std::cout<<"{\"retiring\":"<<m.read_u32(task+4)<<",\"xy_bits\":[";
            for(unsigned i=0;i<(circle || outgoing?1u:2u);++i){
                std::cout<<(i?",[":"[");
                for(unsigned j=0;j<4;++j)std::cout<<(j?",":"")<<std::bit_cast<std::uint32_t>(sprites[i][j]);
                std::cout<<']';
            }
            std::cout<<']';
            if(circle)std::cout<<",\"radius_bits\":"<<m.read_u32(data+12)<<",\"step_bits\":"<<m.read_u32(data+20);
            std::cout<<"}\n";
            if(argc==arg+3){
                auto read=[](const char* path){
                    std::vector<std::uint8_t> pixels(640*448*4);
                    std::ifstream f(path,std::ios::binary);
                    if(!f.read(reinterpret_cast<char*>(pixels.data()),pixels.size()) || f.peek()!=EOF)
                        throw std::runtime_error("Expected a woven RGBA fixture");
                    return pixels;
                };
                platform::RasterFrame frame{640,448,read(argv[arg])};
                const auto old=read(argv[arg+1]);
                for(unsigned field=0;field<2;++field){
                    const auto base=0x1500000+0x8c000*field;m.write_u32(0x236114+field*4,base);
                    for(unsigned y=0;y<224;++y)m.write_bytes(base+2560*y,std::span(old).subspan((2*y+field)*2560,2560));
                }
                if(circle)platform::draw_circlemask_layer(frame,m,texture,passes);
                else platform::draw_screen_slide_layer(frame,m,task);
                std::ofstream f(argv[arg+2],std::ios::binary);
                if(!f.write(reinterpret_cast<const char*>(frame.rgba.data()),frame.rgba.size()))
                    throw std::runtime_error("Cannot write slide result");
            }
            if(circle)release_circlemask(m,task);else release_screen_slide(m,task);
            return 0;
        }
        // Isolated source callback and GS test. The ordinary --route path
        // creates the task through the running scene's cue and scheduler.
        if((argc==11 || argc==13) && (std::string_view(argv[2])=="--gradefilter" ||
                                      std::string_view(argv[2])=="--expandblur")){
            using namespace kx3;
            GuestMemory memory;
            const auto elf=platform::windows::read_disc_resource(argv[1],"SLPM_664.52",
                "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160",1290132);
            memory.write_bytes(0x100000,std::span(elf).subspan(0x1000,0x138648));
            memory.write_u32(0x2388bc,0x320000);
            std::array<std::uint32_t,7> args{};
            for(unsigned i=0;i<7;++i)args[i]=std::uint32_t(std::stoi(argv[3+i]));
            const auto ticks=std::stoul(argv[10]);
            if(ticks>10000)throw std::invalid_argument("Invalid effect probe duration");
            const bool blur=std::string_view(argv[2])=="--expandblur";
            const auto task=blur?create_expandblur(memory,0x1000200,0x182a08,args):create_gradefilter(memory,0x1000200,args);
            for(unsigned i=0;i<ticks;++i){
                const auto callback=memory.read_u32(task+20);
                if(blur){if(callback)update_expandblur(memory,task,callback);}
                else update_gradefilter(memory,task);
            }
            GradeColors color{};BlurDraw sprites{};
            std::cout<<"{\"done\":"<<memory.read_u32(task+16);
            if(blur){
                sprites=draw_expandblur(memory,task);
                std::cout<<",\"sprites\":[";
                for(const auto& s:sprites){
                    if(&s!=&sprites.front())std::cout<<',';
                    std::cout<<'[';
                    for(const auto value:s.uv)std::cout<<std::bit_cast<std::uint32_t>(value)<<',';
                    std::cout<<s.alpha<<']';
                }
                std::cout<<"]}\n";
            }else{
                color=draw_gradefilter(memory,task);
                std::cout<<",\"rgb\":["<<color.top[0]<<','<<color.top[1]<<','<<color.top[2]<<','
                         <<color.bottom[0]<<','<<color.bottom[1]<<','<<color.bottom[2]<<"]}\n";
            }
            if(argc==13){
                platform::RasterFrame frame{640,448,std::vector<std::uint8_t>(640*448*4)};
                std::ifstream in(argv[11],std::ios::binary);
                if(!in.read(reinterpret_cast<char*>(frame.rgba.data()),frame.rgba.size()) || in.peek()!=EOF)
                    throw std::runtime_error("Expected 640x448 RGBA input");
                if(blur)platform::draw_expandblur_layer(frame,sprites);
                else platform::draw_gradefilter_layer(frame,color);
                std::ofstream out(argv[12],std::ios::binary);
                if(!out.write(reinterpret_cast<const char*>(frame.rgba.data()),frame.rgba.size()))
                    throw std::runtime_error("Cannot write grade filter sample");
            }
            if(blur)release_expandblur(memory,task);else release_gradefilter(memory,task);
            return 0;
        }
        if(argc==5 && std::string_view(argv[3])=="--actor-test"){
            using kx3::platform::windows::ProjectGame;
            auto game=std::string_view(argv[4])=="-"?std::make_unique<ProjectGame>(argv[1],argv[2],4357u):
                                                     ProjectGame::load(argv[1],argv[2],argv[4]);
            probe_actor(*game);return 0;
        }
        if(argc==5 && std::string_view(argv[3])=="--wait-test")
            return probe_wait(argv[1],argv[2],std::stoul(argv[4]),false);
        if(argc==5 && std::string_view(argv[3])=="--save-first-choice")
            return probe_wait(argv[1],argv[2],10000,true,true,{},{},false,{},{},argv[4]);
        if(argc==4 && std::string_view(argv[3])=="--preview-names"){
            using namespace kx3::platform::windows;
            if(std::string_view(argv[2])!="sn4")throw std::invalid_argument("Expected the sn4 scene pack");
            ProjectGame game(argv[1],argv[2],4357u);ProjectImageServices files(argv[1]);
            const auto spk=read_disc_resource(argv[1],"SCENARIO/sn4.spk",
                "a2747e5311ec8747acd6e492fa8c055822f98f764ed8704d86397ae9514b32e1",329728);
            kx3::GuestMemory m;m.write_bytes(0,game.memory().bytes(0,m.size));
            struct Case{unsigned at;const char* name;const char* resolved;};
            constexpr Case cases[]={{0xb4f0,"my0033.m2s","my0033.ipu"},{0xb0df,"my0003.mmv","my0003.m2v"},
                {0xb6f2,"my0063.pss","my0063.ipu"},{0,"kx3_missing.pss","sy0000b.ipu"}};
            for(const auto& c:cases){
                std::string name=c.name,preview;
                if(c.at && (std::string_view(reinterpret_cast<const char*>(spk.data()+c.at),name.size())!=name ||
                   spk.at(c.at+name.size())))throw std::runtime_error("Missing original ScenePack filename");
                m.write_u32(0x206818,0);
                if(kx3::resolve_preview_filename(m,files,name,preview) || name!=c.name || !preview.empty())
                    throw std::runtime_error("Inactive preview changed the resource");
                m.write_u32(0x206818,1);
                if(!kx3::resolve_preview_filename(m,files,name,preview) || name!=c.resolved ||
                   preview!="MOVIE/"+std::string(c.name) || !files.source_file_size("MOVIE/"+name))
                    throw std::runtime_error("Original 137B98 selected an unexpected movie");
                std::cout<<"{\"spk_offset\":"<<c.at<<",\"source\":"<<std::quoted(c.name)<<",\"resolved\":"<<std::quoted(name)
                         <<",\"preview\":"<<std::quoted(preview)<<",\"controlled_missing\":"<<(c.at?"false":"true")<<"}\n";
            }
            return 0;
        }
        if(argc>=6 && argc<=7 && std::string_view(argv[3])=="--answer-record"){
            kx3::platform::windows::ProjectGame game(argv[1],argv[2],4357u);
            const unsigned selector=std::stoul(argv[4],nullptr,0),offset=std::stoul(argv[5],nullptr,0);
            const auto& m=game.memory();const auto manager=game.runtime().manager,script=m.read_u32(manager+0x38);
            const auto base=m.read_u32(script+4),control=m.read_u32(manager+0x34);
            const auto op=m.read_u8(base+offset);
            if(op!=0x81 && op!=0x82)throw std::invalid_argument("Expected a retail answer record");
            game.enter_record_for_probe(selector,offset);
            std::vector<kx3::ChoiceInput> keys(1);
            if(argc==7){std::istringstream stream(argv[6]);std::string word;
                while(std::getline(stream,word,',')){
                    kx3::ChoiceInput input;
                    if(word.starts_with("m")){input.name_index=std::stoi(word.substr(1));input.name_confirm=true;}
                    else {auto mask=std::stoul(word,nullptr,0);if(mask>0xffff)throw std::invalid_argument("Invalid pad mask");
                        input.held=std::uint16_t(mask);}
                    keys.push_back(input);
                }}
            for(auto input:keys){
                game.advance(input);
                const auto editor=m.read_u32(control+8);
                const auto id=m.read_u32(script+0xd4),count=m.read_u32(script+0xc8);
                std::string label;
                if(id<count){const auto record=m.read_u32(m.read_u32(script+0xcc)+4*id);
                    if(record){const auto str=m.bytes(record+8,32);label.assign(str.begin(),std::find(str.begin(),str.end(),0));}}
                std::cout<<"{\"key\":"<<input.held<<",\"mouse\":"<<input.name_index<<",\"op\":"<<int(op)<<",\"context\":"<<m.read_u32(manager+0x40)
                         <<",\"open\":"<<m.read_u32(control)<<",\"editor\":"<<editor<<",\"vtable\":"<<(editor?m.read_u32(editor):0)
                         <<",\"slot\":"<<(editor?m.read_u32(editor+8):0)<<",\"x\":"<<(editor?m.read_u32(editor+0x50):0)
                         <<",\"y\":"<<(editor?m.read_u32(editor+0x54):0)<<",\"label\":"<<std::quoted(label)
                         <<",\"offset\":"<<m.read_u32(script+0xd8)-base<<"}\n";
            }
            return 0;
        }
        if(argc==7 && std::string_view(argv[3])=="--scene-checkpoint"){
            kx3::platform::windows::ProjectGame game(argv[1],argv[2],4357);
            const unsigned selector=std::stoul(argv[4],nullptr,0),offset=std::stoul(argv[5],nullptr,0);
            game.prepare_choice_layout_for_probe();
            game.enter_record_for_probe(selector,offset);
            const auto& m=game.memory();const auto script=m.read_u32(game.runtime().manager+0x38);
            if(m.read_u8(m.read_u32(script+0xd8))!=0x73)throw std::invalid_argument("Expected original scene selection");
            game.advance({});
            game.save(argv[6]);
            std::cout<<"{\"stage\":\"isolated-scene-start\",\"selector\":"<<selector<<",\"offset\":"<<offset
                     <<",\"tick\":"<<game.logical_tick()<<"}\n";
            return 0;
        }
        if((argc==8 || argc==9) && std::string_view(argv[3])=="--choice-record"){
            const auto selector=unsigned(std::stoul(argv[4],nullptr,0));
            const auto offset=unsigned(std::stoul(argv[5],nullptr,0));
            const auto option=unsigned(std::stoul(argv[6],nullptr,0));
            kx3::platform::windows::ProjectGame game(argv[1],argv[2],4357);
            const auto& m=game.memory();
            const auto owner=game.runtime().manager,script=m.read_u32(owner+0x38);
            if(m.read_u8(m.read_u32(script+4)+offset)!=0x6c)
                throw std::invalid_argument("Choice record probe requires original 6C");
            game.prepare_choice_layout_for_probe();
            game.enter_record_for_probe(selector,offset);
            for(unsigned i=0;i<600 && m.read_u32(owner+0x40)!=m.read_u32(0x235f04);++i)
                game.advance(kx3::ChoiceInput{});
            if(m.read_u32(owner+0x40)!=m.read_u32(0x235f04))
                throw std::runtime_error("Original choice did not reach interactive context");
            std::cout<<"{\"stage\":\"isolated-choice-ready\",\"selector\":"<<selector
                     <<",\"offset\":"<<offset<<",\"count\":"<<m.read_u32(m.read_u32(owner+8)+4)
                     <<",\"tick\":"<<game.logical_tick()<<"}\n";
            probe_choice(game,argv[7],option);
            if(argc==9)game.save(argv[8]);
            return 0;
        }
        if((argc==6 || argc==7) && std::string_view(argv[3])=="--readback-choice"){
            auto game=kx3::platform::windows::ProjectGame::load(argv[1],argv[2],argv[4]);
            const auto& m=game->memory();const auto manager=game->runtime().manager,helper=m.read_u32(manager+4);
            const auto script=m.read_u32(manager+0x38),choice=m.read_u32(manager+8);
            if(m.read_u32(manager+0x40)!=m.read_u32(0x235f04) || m.read_u32(choice+0x168))
                throw std::runtime_error("Expected original choice at its first option");
            const auto base=m.read_u32(script+4);
            auto state=[&](const char* stage){
                const auto path=[&](unsigned address){
                    const auto s=m.bytes(address,23);return std::string(s.begin(),std::find(s.begin(),s.end(),0));
                };
                std::cout<<"{\"stage\":"<<std::quoted(stage)<<",\"tick\":"<<game->logical_tick()
                         <<",\"context\":"<<m.read_u32(m.read_u32(manager+0x40))<<",\"selector\":"<<m.read_u32(script+0xd0)
                         <<",\"label\":"<<m.read_u32(script+0xd4)<<",\"offset\":"<<m.read_u32(script+0xd8)-base
                         <<",\"readback\":"<<m.read_u32(helper+4)<<",\"focus\":"<<m.read_u32(choice+0x168)
                         <<",\"loader\":"<<m.read_u32(0x206250)<<",\"primary\":"<<std::quoted(path(0x2070c2))
                         <<",\"preview\":"<<std::quoted(path(0x2070d9))<<"}\n";
            };
            state("before");game->advance(kx3::ChoiceInput{});game->advance(kx3::ChoiceInput{.held=0x10});state("up");
            if(!m.read_u32(helper+4))throw std::runtime_error("First Up did not enter original readback");
            for(unsigned i=0;i<60;++i)game->advance(kx3::ChoiceInput{});
            state("settled");
            const auto mask=std::stoul(argv[5],nullptr,0);
            if(mask>0xffff)throw std::invalid_argument("Invalid pad mask");
            game->advance(kx3::ChoiceInput{.held=std::uint16_t(mask)});state("key");
            const unsigned after=argc==7?std::stoul(argv[6]):60u;
            if(after>3600)throw std::invalid_argument("Invalid readback update limit");
            for(unsigned i=0;i<after;++i)game->advance(kx3::ChoiceInput{});
            state("after");return 0;
        }
        if(argc>=5 && (std::string_view(argv[3])=="--walk" || std::string_view(argv[3])=="--route")){
            const bool route=std::string_view(argv[3])=="--route";
            int first=5;
            std::filesystem::path save_at_limit,trace_dir,from;
            if(route && first+1<argc && std::string_view(argv[first])=="--from"){
                from=argv[first+1];first+=2;
            }
            if(route && first+1<argc && std::string_view(argv[first])=="--save"){
                save_at_limit=argv[first+1];first+=2;
            }
            std::filesystem::path witness_store;
            if(route && first+1<argc && std::string_view(argv[first])=="--witness-store"){
                witness_store=argv[first+1];first+=2;
            }
            std::optional<unsigned> until_ending;
            if(route && first+1<argc && std::string_view(argv[first])=="--until-ending"){
                until_ending=std::stoul(argv[first+1]);first+=2;
            }
            if(route && first+1<argc && std::string_view(argv[first])=="--trace-expandband"){
                trace_dir=argv[first+1];first+=2;
            }
            const bool names=first<argc && std::string_view(argv[first])=="--accept-default-names";
            if(names)++first;
            if(first==argc)return probe_wait(argv[1],argv[2],std::stoul(argv[4]),true,names,{}, {},route,save_at_limit,trace_dir,{},from,until_ending,witness_store);
            if(first+2<=argc && (route || first+2==argc)){
                std::vector<unsigned> options;
                for(int i=first+1;i<argc;++i){
                    std::size_t consumed=0;const auto index=std::stoul(argv[i],&consumed);
                    if(consumed!=std::string_view(argv[i]).size() || index>=10)throw std::invalid_argument("Invalid source option index");
                    options.push_back(unsigned(index));
                }
                return probe_wait(argv[1],argv[2],std::stoul(argv[4]),true,names,argv[first],std::move(options),route,save_at_limit,trace_dir,{},from,until_ending,witness_store);
            }
            throw std::invalid_argument("--route frames [--from checkpoint] [--save destination] [--accept-default-names] [mouse|keyboard option ...]");
        }
        if(argc==5 && std::string_view(argv[3])=="--device") {
            kx3::platform::windows::ProjectGame game(argv[1],argv[2]);
            game.enable_audio_output();
            const auto limit=std::stoul(argv[4]);
            if(limit>5000)throw std::invalid_argument("Invalid audio clock probe duration");
            unsigned peak=0;
            for(unsigned n=0;n<limit;++n){
                game.advance(kx3::ChoiceInput{});
                if(!game.audio_output_error().empty())throw std::runtime_error(game.audio_output_error());
                for(auto sample:game.last_audio())peak=std::max(peak,unsigned(std::abs(int(sample))));
                const auto frames=game.played_audio_frames();
                if(peak && frames>=1600){
                    std::cout<<"{\"tick\":"<<game.logical_tick()<<",\"played_stereo_frames\":"<<frames
                             <<",\"source_pcm_peak\":"<<peak<<"}\n";
                    return 0;
                }
            }
            throw std::runtime_error("No non-silent PCM or advancing Windows device clock within the probe interval");
        }
        if(argc>=4 && std::string_view(argv[2])=="--movie-audio"){
            using namespace kx3::platform;
            for(int i=3;i<argc;++i){
                const auto* binding=find_original_media(argv[i]);
                if(!binding)throw std::runtime_error("Unknown original movie");
                const auto movie=windows::prepare_original_movie(argv[1],argv[i],binding->size);
                if(!movie->audio)throw std::runtime_error("Movie has no encoded original audio");
                const auto& timing=movie->timing.at(0);
                const auto end=kx3::pss_duration(timing);
                if(end>48000ull*600)throw std::runtime_error("Movie timeline exceeds test allocation");
                kx3::MoviePosition position{.active=true};
                windows::ProjectMixer mixer;
                std::vector<std::int16_t> result;result.reserve(((end+799)/800)*1600);
                while(position.active){
                    auto block=mixer.mix_tick(movie.get(),position);
                    result.insert(result.end(),block.begin(),block.end());
                    kx3::advance_movie_clock(position,movie->timing);
                }
                if(position.sample!=end)throw std::runtime_error("A/V clock did not reach exact end");
                const auto bytes=std::span(reinterpret_cast<const std::uint8_t*>(result.data()),result.size()*2);
                std::cout<<"{\"name\":"<<std::quoted(binding->name)<<",\"audio_start\":"<<timing.audio_start_sample
                         <<",\"video_start\":"<<timing.video_start_sample<<",\"samples\":"<<result.size()/2
                         <<",\"rgba_frames\":"<<timing.frames<<",\"sha256\":"<<std::quoted(windows::source_bytes_sha256(bytes))<<"}\n";
            }
            return 0;
        }
        if(argc>=4 && std::string_view(argv[2])=="--music") {
            kx3::platform::windows::ProjectImageServices resources(argv[1]);
            for(int i=3;i<argc;++i) {
                const auto music=resources.open_music(argv[i]);
                const auto& pcm=music->pcm.interleaved;
                const auto bytes=std::span(reinterpret_cast<const std::uint8_t*>(pcm.data()),pcm.size()*2);
                std::cout<<"{\"name\":"<<std::quoted(music->name)<<",\"frames\":"<<pcm.size()/music->pcm.channels
                         <<",\"channels\":"<<music->pcm.channels<<",\"rate\":"<<music->pcm.rate
                         <<",\"loop_start\":"<<music->loop_start<<",\"loop_end\":"<<music->loop_end
                         <<",\"sha\":"<<std::quoted(kx3::platform::windows::source_bytes_sha256(bytes))<<"}\n";
            }
            return 0;
        }
        if(argc>=4 && std::string_view(argv[2])=="--ipu") {
            using namespace kx3::platform;
            for(int i=3;i<argc;++i) {
                const auto* binding=find_original_media(argv[i]);
                if(!binding)throw std::runtime_error("Unknown original media name");
                auto bytes=windows::read_disc_resource(argv[1],binding->path,binding->sha,binding->size);
                auto frame=windows::decode_original_ipu(argv[1],std::move(bytes));
                std::cout<<"{\"name\":"<<std::quoted(binding->name)<<",\"width\":"<<frame->width<<",\"height\":"<<frame->height
                         <<",\"sha\":"<<std::quoted(windows::source_bytes_sha256(frame->rgba))<<"}\n";
            }
            return 0;
        }
        if(argc==5 && std::string_view(argv[3])=="--initial-ram"){
            kx3::platform::windows::ProjectGame game(argv[1],argv[2],4357u);
            std::ofstream out(argv[4],std::ios::binary);
            const auto bytes=game.memory().bytes(0,kx3::GuestMemory::size);
            if(!out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()))throw std::runtime_error("Cannot export initial RAM");
            std::cout<<"{\"tick\":0,\"manager\":"<<game.runtime().manager<<",\"ram_sha256\":"
                     <<std::quoted(kx3::platform::windows::source_bytes_sha256(bytes))<<"}\n";return 0;
        }
        if(argc==5 && std::string_view(argv[3])=="--migrate-memory-fixture"){
            std::ifstream f(argv[4],std::ios::binary|std::ios::ate);
            if(!f || f.tellg()!=kx3::GuestMemory::size)throw std::runtime_error("Expected retail-size guest RAM");
            std::vector<std::uint8_t> snapshot(kx3::GuestMemory::size);
            f.seekg(0);if(!f.read(reinterpret_cast<char*>(snapshot.data()),snapshot.size()))throw std::runtime_error("Incomplete fixture");
            kx3::GuestMemory m;m.write_bytes(0,snapshot);
            const auto mgr=m.read_u32(0x235e40);
            if(m.read_u32(mgr+0x10) || m.read_u32(0x2387d0)!=0xd4 || m.read_u32(0x236730)!=8)
                throw std::runtime_error("Expected an active pre-constructor memory panel");
            kx3::restore_missing_panel_modes(m,mgr);
            const auto mode=m.read_u32(mgr+0x10);
            if(!std::equal(snapshot.begin(),snapshot.begin()+0x118,m.bytes(mode,0x118).begin()) ||
               m.read_u32(0x2387d0)!=mode+0xd4 || m.read_u32(0x2387d4)!=mode+12 || m.read_u32(0x236730)!=mode+8)
                throw std::runtime_error("Legacy live option table or result pointer lost");
            using kx3::platform::windows::source_bytes_sha256;
            const auto digest=source_bytes_sha256(m.bytes(0,m.size));
            kx3::restore_missing_panel_modes(m,mgr);
            if(digest!=source_bytes_sha256(m.bytes(0,m.size)))throw std::runtime_error("Migration was not idempotent");
            std::cout<<"{\"status\":\"verified\",\"mode\":"<<mode<<",\"option_count\":"<<m.read_u32(mode+4)
                     <<",\"idempotent_sha256\":"<<std::quoted(digest)<<"}\n";return 0;
        }
        if((argc==6 || argc==7) && std::string_view(argv[3])=="--symbol-record"){
            const auto sel=unsigned(std::stoul(argv[4])),offset=unsigned(std::stoul(argv[5]));
            kx3::platform::windows::ProjectGame game(argv[1],argv[2],4357);
            const auto& m=game.memory();const auto script=m.read_u32(game.runtime().manager+0x38),base=m.read_u32(script+4);
            game.enter_record_for_probe(sel,argc==7?unsigned(std::stoul(argv[6])):offset);
            std::map<unsigned,int> art;
            const unsigned start=base+offset;
            unsigned end=start+1;
            while(m.read_u8(end)!=3 && end-start<4096)end+=2;
            if(m.read_u8(start)!=2 || end-start>=4096)throw std::runtime_error("Not a source text record");
            std::set<unsigned> required;
            for(auto a=start+1;a<end;a+=2)if(m.read_u8(a)!=0x81 || m.read_u8(a+1)!=0x40)required.insert(a-start);
            for(unsigned i=0;i<2400 && !required.empty();++i){
                const auto context=m.read_u32(game.runtime().manager+0x40);
                const bool waiting=context==m.read_u32(0x235f34) || context==m.read_u32(0x235f38);
                const auto update=game.advance(kx3::ChoiceInput{.held=std::uint16_t(waiting && i%2?0x2000:0)});
                for(const auto& e:update.glyphs)if(e.source.source_address>start && e.source.source_address<end)
                    {art[e.source.source_address-start]=e.resource_atlas;required.erase(e.source.source_address-start);}
            }
            std::cout<<"{\"offset\":"<<offset<<",\"units\":"<<art.size()<<",\"art_units\":"
                     <<std::count_if(art.begin(),art.end(),[](const auto& item){return item.second>=0;})<<",\"undrawn_offsets\":[";
            bool comma=false;for(auto a:required){if(comma)std::cout<<',';std::cout<<a;comma=true;}std::cout<<"]}\n";
            return required.empty()?0:3;
        }
        if(argc==6 && (std::string_view(argv[3])=="--ending-transition" || std::string_view(argv[3])=="--ending-epilogue" ||
                       std::string_view(argv[3])=="--ending-return")){
            const auto selector=unsigned(std::stoul(argv[4])),offset=unsigned(std::stoul(argv[5]));
            kx3::platform::windows::ProjectGame game(argv[1],argv[2],4357);
            const auto& m=game.memory();
            const auto script=m.read_u32(game.runtime().manager+0x38),base=m.read_u32(script+4);
            if(m.read_u8(base+offset)!=0x47 || m.read_u8(base+offset+1)!=4)throw std::invalid_argument("Wrong ending record");
            game.enter_record_for_probe(selector,offset);
            const auto prior=m.read_u32(0x206260);
            const bool returning=std::string_view(argv[3])=="--ending-return";
            const bool epilogue=returning || std::string_view(argv[3])=="--ending-epilogue";
            const unsigned dest=std::string_view(argv[2])=="sn4g"?16:3;
            bool started=false,drawn=false,closed=false,entered=false,at_top=false;
            unsigned restored=0,after_label=0;
            for(unsigned i=0;i<(returning?12000u:1800u);++i){
                kx3::ChoiceInput input;
                if(closed && i%40==35)input.held=0x2000;
                try{game.advance(input);}catch(const std::exception& e){
                    std::cerr<<"Ending record "<<offset<<" tick "<<i<<" started "<<started<<" drawn "<<drawn<<" closed "<<closed
                             <<" cursor 0x"<<std::hex<<m.read_u32(script+0xd8)-base<<" : "<<e.what()<<'\n';return 2;
                }
                if(m.read_u32(0x236484)==0x207488){
                    if(!started && m.read_u32(0x206260)!=100)throw std::runtime_error("148E60 did not set original field");
                    started=true;drawn|=m.read_u32(0x236528)!=0;
                }else if(started && !closed){
                    closed=true;restored=m.read_u32(0x206260);
                    if(!epilogue)break;
                }
                if(!entered && closed && m.read_u32(script+0xd0)==dest){
                    entered=true;after_label=m.read_u32(script+0xd4);
                    if(!returning)break;
                }
                if(returning && entered && m.read_u32(script+0xd0)!=dest){
                    const auto table=m.read_u32(script+0xcc),id=m.read_u32(script+0xd4);
                    if(id<m.read_u32(script+0xc8)){
                        const auto name=m.read_u32(table+id*4)+8;
                        at_top=std::ranges::equal(m.bytes(name,11),m.bytes(base+0x20,11));
                        if(at_top)break;
                    }
                }
            }
            std::cout<<"{\"program\":\""<<argv[2]<<"\",\"selector\":"<<selector<<",\"record\":"<<offset
                     <<",\"ticks\":"<<game.logical_tick()<<",\"started\":"<<started<<",\"drawn\":"<<drawn
                     <<",\"closed\":"<<closed<<",\"before\":"<<prior<<",\"after\":"<<restored
                     <<",\"epilogue_selector_entered\":"<<entered<<",\"active_label\":"<<after_label
                     <<",\"returned_to_disc_start_label\":"<<at_top<<",\"last_selector\":"<<m.read_u32(script+0xd0)
                     <<",\"last_label\":"<<m.read_u32(script+0xd4)
                     <<",\"cursor_offset\":"<<m.read_u32(script+0xd8)-base<<"}\n";
            return started && drawn && closed && prior==restored && (!epilogue || entered) && (!returning || at_top)?0:3;
        }
        if((argc==5 || argc==6) && (std::string_view(argv[3])=="--mystery-panel" || std::string_view(argv[3])=="--mystery-record")){
            const bool culprit=std::string_view(argv[4])=="culprit";
            if(!culprit && std::string_view(argv[4])!="memory")throw std::invalid_argument("Unknown panel");
            kx3::platform::windows::ProjectGame game(argv[1],"sn4",4357);
            // Actual strings in the original SN4 label tables.
            const bool direct=std::string_view(argv[3])=="--mystery-record";
            if(direct)game.enter_record_for_probe(culprit?0:1,culprit?248379:454138);
            else game.enter_label_for_probe(culprit?0:1,culprit?0x57dc:0x4c8c4);
            unsigned shown=0,drawn=0,max_sprites=0;
            unsigned last_selector=0,last_cursor=0;
            for(unsigned i=0;i<1800;++i){
                kx3::ChoiceInput input;
                if(shown)input.held=shown==40?0x20:shown==48?0x2000:0;
                else if(i%40==35)input.held=0x2000;
                try{game.advance(input);}catch(const std::exception& e){
                    std::cerr<<"Panel probe stopped at tick "<<i<<" shown "<<shown<<" cursor 0x"<<std::hex<<last_cursor
                             <<" selector "<<last_selector<<" : "<<e.what()<<'\n';return 2;
                }
                const auto& m=game.memory();const auto script=m.read_u32(game.runtime().manager+0x38);
                last_cursor=m.read_u32(script+0xd8);last_selector=m.read_u32(script+0xd0);
                if(!kx3::mystery::active(m)){if(shown)break;continue;}
                ++shown;
                const unsigned sprites=m.read_u32(kx3::mystery::sprite_count);
                if(argc==6 && sprites && kx3::mystery::selected(m)>=0){
                    const auto bytes=m.bytes(0,m.size);std::ofstream out(argv[5],std::ios::binary);
                    if(!out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()))throw std::runtime_error("Could not export panel RAM");
                    std::cout<<"{\"ready_tick\":"<<game.logical_tick()<<",\"selected\":"<<kx3::mystery::selected(m)
                             <<",\"sprites\":"<<sprites<<"}\n";return 0;
                }
                drawn+=sprites!=0;max_sprites=std::max(max_sprites,sprites);
            }
            const auto& m=game.memory();
            std::cout<<"{\"origin\":\""<<(direct?(culprit?"record 248379":"record 454138"):(culprit?"my29_0265":"myb19_0100"))<<"\",\"ticks\":"<<game.logical_tick()
                     <<",\"shown\":"<<shown<<",\"drawn\":"<<drawn<<",\"max_sprites\":"<<max_sprites
                     <<",\"closed\":"<<!kx3::mystery::active(m)<<",\"selector\":"<<last_selector<<",\"cursor\":"<<last_cursor<<"}\n";
            return drawn && !kx3::mystery::active(m)?0:3;
        }
        if((argc==7 || argc==8) && std::string_view(argv[3])=="--vm-record"){
            using u32=std::uint32_t;
            const auto sel=u32(std::stoul(argv[4],nullptr,0)),off=u32(std::stoul(argv[5],nullptr,0)),
                       slot=u32(std::stoul(argv[6],nullptr,0));
            if(sel>=32 || (slot!=3 && slot!=15 && slot!=16))throw std::invalid_argument("Invalid VM probe context");
            kx3::platform::windows::ProjectGame image(argv[1],argv[2],4357);
            kx3::GuestMemory m;m.write_bytes(0,image.memory().bytes(0,m.size));
            const auto manager=image.runtime().manager,script=m.read_u32(manager+0x38);
            const auto block=m.read_u32(script+8+4*sel),base=m.read_u32(script+4),address=base+off;
            if(!block || address<m.read_u32(block+0x430))throw std::invalid_argument("Record outside selected block");
            const auto offset=address-m.read_u32(block+0x430);
            const auto op=m.read_u8(address);
            kx3::invoke_recovered(m,0x10d830,script,sel,offset+1);
            const u32 handler=u32(kx3::invoke_recovered(m,0x1133b0,manager,op));
            const auto method=m.read_u32(m.read_u32(handler)+4*slot),context=m.read_u32(manager+0x40);
            if(argc==8){
                std::ofstream out(argv[7],std::ios::binary);const auto bytes=m.bytes(0,m.size);
                if(!out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()))throw std::runtime_error("Cannot save VM input fixture");
            }
            kx3::GuestMemory::AccessBudget budget(m,16000000);
            kx3::GuestMemory::Transaction tx(m);
            const auto result=kx3::invoke_recovered(m,method,handler,context,offset,op);
            tx.commit();
            std::cout<<"{\"opcode\":"<<unsigned(op)<<",\"slot\":"<<slot<<",\"entry\":"<<method<<",\"self\":"<<handler
                     <<",\"a1\":"<<context<<",\"a2\":"<<offset<<",\"a3\":"<<unsigned(op)<<",\"v0\":"<<result
                     <<",\"selector\":"<<m.read_u32(script+0xd0)<<",\"cursor\":"<<m.read_u32(script+0xd8)
                     <<",\"script_base\":"<<base<<",\"origin\":"<<address<<"}\n";return 0;
        }
        if(argc==5 && (std::string_view(argv[3])=="--credits" || std::string_view(argv[3])=="--credits-scene" ||
                       std::string_view(argv[3])=="--credits-to-end")){
            kx3::platform::windows::ProjectGame game(argv[1],argv[2]);
            if(std::string_view(argv[3])=="--credits")game.enter_staff_roll_for_probe();
            else if(std::string_view(argv[2])=="sn4")game.enter_label_for_probe(0,0x4a0fe);
            else if(std::string_view(argv[2])=="sn4g")game.enter_label_for_probe(0,0x4f4a);
            else game.enter_label_for_probe(1,0x50673);
            unsigned lines=0;bool started=false,reached_eof=false,finished=false,confirmed=false;
            std::set<unsigned> offsets;
            const auto limit=std::stoul(argv[4]);
            for(unsigned i=0;i<limit;++i){
                const auto& before=game.memory();const auto manager=game.runtime().manager;
                // First work, mmb14 staff sequence 0x5094A: 51 FF FF FF FF.
                // Allow the chapter's actual confirm edge once the last credited name has scrolled in.
                if(std::string_view(argv[3])=="--credits-to-end" && std::string_view(argv[2])=="sn2" &&
                   !confirmed && offsets.contains(3592) && before.read_u32(manager+0x2e8) && before.read_u32(manager+0x2ec)){
                    kx3::ChoiceInput input;input.held=0x2000;game.advance(input);confirmed=true;
                }else game.advance({});
                const auto& m=game.memory();
                reached_eof|=m.read_u32(0x236804)!=0;
                if(started && !m.read_u32(0x236824)){finished=true;break;}
                started|=m.read_u32(0x236824)!=0;
                const auto visible=kx3::credits::visible_lines(game.memory());
                lines+=visible.size();
                for(const auto& l:visible)offsets.insert(l.offset);
                if(std::string_view(argv[3])!="--credits-to-end" && !visible.empty() && (lines==visible.size() || i%240==0))
                    std::cout<<"{\"tick\":"<<i+1<<",\"rows\":"<<visible.size()<<",\"first_offset\":"<<visible.front().offset<<"}\n";
            }
            std::cout<<"{\"visible_samples\":"<<lines<<",\"distinct_lines\":"<<offsets.size()<<",\"source_offsets\":[";
            bool first=true;
            for(auto offset:offsets){if(!first)std::cout<<',';std::cout<<offset;first=false;}
            std::cout<<"]"
                     <<",\"started\":"<<started<<",\"source_eof\":"<<reached_eof<<",\"confirmed\":"<<confirmed
                     <<",\"end_command\":"<<finished<<"}\n";
            return std::string_view(argv[3])=="--credits-to-end" && !finished?3:0;
        }
        if(argc==7 && std::string_view(argv[3])=="--note-resume"){
            const auto ticks=std::stoul(argv[6]);if(ticks>2000)throw std::invalid_argument("Invalid note resume duration");
            auto game=kx3::platform::windows::ProjectGame::load_note(argv[1],argv[2],std::filesystem::path(argv[4])/"system.dat",
                                                                    unsigned(std::stoul(argv[5])));
            const auto& m=game->memory();const auto manager=game->runtime().manager;
            const auto script=m.read_u32(manager+0x38);
            auto report=[&]{std::cout<<"{\"tick\":"<<game->logical_tick()<<",\"context\":"<<m.read_u32(m.read_u32(m.read_u32(manager+0x40)))
                <<",\"selector\":"<<m.read_u32(script+0xd0)<<",\"label\":"<<m.read_u32(script+0xd4)
                <<",\"cursor\":"<<m.read_u32(script+0xd8)<<",\"card_load_result\":"<<m.read_u32(0x235b48)<<"}"<<std::endl;};
            report();for(unsigned i=0;i<ticks;++i)game->advance(kx3::ChoiceInput{});report();return 0;
        }
        if((argc==7 || argc==8) && std::string_view(argv[3])=="--chapter-actions"){
            using kx3::platform::windows::ProjectGame;
            auto game=ProjectGame::load(argv[1],argv[2],argv[4]);
            if(argc==8)game->set_system_record_file(std::filesystem::path(argv[7])/"system.kx3record");
            std::istringstream actions(argv[5]);
            std::string action;
            std::array<std::uint32_t,7> previous{};
            unsigned total=0;
            while(std::getline(actions,action,',')){
                const auto split=action.find(':');
                if(split==std::string::npos)throw std::invalid_argument("Expected ticks:pad");
                std::size_t used=0;
                const auto ticks=std::stoul(action.substr(0,split),&used);
                if(used!=split || ticks>2000-total)throw std::invalid_argument("Invalid duration");
                const auto pad=std::stoul(action.substr(split+1),&used,0);
                if(used!=action.size()-split-1 || pad>65535)throw std::invalid_argument("Invalid pad mask");
                total+=ticks;
                for(unsigned i=0;i<ticks;++i){
                    game->advance(kx3::ChoiceInput{.held=static_cast<std::uint16_t>(pad)});
                    const auto& m=game->memory();
                    const std::array state{m.read_u32(0x2388e8),m.read_u32(0x2380d0),m.read_u32(0x238058),
                        m.read_u32(0x2380a0),m.read_u32(0x239f44),m.read_u32(0x235b4c),m.read_u32(0x235b58)};
                    if(state!=previous){
                        std::cout<<game->logical_tick();
                        for(auto x:state)std::cout<<' '<<std::hex<<x;
                        std::cout<<std::dec<<std::endl;
                        previous=state;
                    }
                }
            }
            game->save(argv[6]);
            return 0;
        }
        if(argc==7 && (std::string_view(argv[3])=="--checkpoint" || std::string_view(argv[3])=="--walk-checkpoint")) {
            const auto root=std::filesystem::path(argv[1]);
            const auto ticks=std::stoul(argv[4]);
            if(ticks>100000)throw std::invalid_argument("Invalid checkpoint test duration");
            using kx3::platform::windows::ProjectGame;
            auto game=std::string_view(argv[5])=="-"?std::make_unique<ProjectGame>(root,argv[2],4357u):
                                                     ProjectGame::load(root,argv[2],argv[5]);
            const bool walk=std::string_view(argv[3])=="--walk-checkpoint";
            for(unsigned i=0;i<ticks;++i){
                const auto& m=game->memory();
                const auto context=m.read_u32(game->runtime().manager+0x40);
                const auto wait=context==m.read_u32(0x235f34) || context==m.read_u32(0x235f38);
                const std::uint16_t buttons=walk && wait && !(m.read_u16(0x1e41c60+8)&0x2000)?0x2000:0;
                game->advance(kx3::ChoiceInput{.held=buttons});
            }
            game->save(argv[6]);
            const auto pcm=std::span(reinterpret_cast<const std::uint8_t*>(game->last_audio().data()),sizeof(kx3::platform::windows::StereoBlock));
            const auto& music=game->mixer().music();
            const auto scene=game->scene_frame();
            std::cout<<"{\"tick\":"<<game->logical_tick()<<",\"visible_text_events\":"<<game->visible_text_events().size()
                     <<",\"visible_scene\":"<<game->images().current_generation()<<",\"voices\":"<<game->mixer().voices().size()
                     <<",\"music\":"<<std::quoted(music?music->track->name:std::string())<<",\"music_frame\":"<<(music?music->frame:0)
                     <<",\"music_ramp_length\":"<<(music?music->ramp_length:0)
                     <<",\"music_ramp_elapsed\":"<<(music?music->ramp_elapsed:0)
                     <<",\"member\":"<<game->images().visible_member()<<",\"frame\":"<<game->images().visible_frame()
                     <<",\"resident_groups\":"<<game->images().prepared().size()
                     <<",\"card_request\":"<<game->memory().read_u32(0x239fa4)
                     <<",\"cue_head\":"<<game->memory().read_u32(0x206dd0)<<",\"cue_tail\":"<<game->memory().read_u32(0x206dcc)
                     <<",\"scene_sha256\":"<<std::quoted(scene?kx3::platform::windows::source_bytes_sha256(scene->rgba):std::string())
                     <<",\"audio_sha256\":"<<std::quoted(kx3::platform::windows::source_bytes_sha256(pcm))
                     <<",\"ram_sha256\":"<<std::quoted(kx3::platform::windows::source_bytes_sha256(game->memory().bytes(0,kx3::GuestMemory::size)))<<"}\n";
            return 0;
        }
        if(argc>=4 && std::string_view(argv[2])=="--sound") {
            using namespace kx3::platform::windows;
            const auto bank=read_disc_resource(argv[1],"SOUND/SSDVDAT/se.dat",
                "e481a5823ee83d6f67e16b4aabbc93807f2790eb8ec17c34b609aa658285c51c",50339840);
            for (int i=3; i<argc; ++i) {
                const auto id=std::stoul(argv[i]); const auto record=kx3::find_bank_sound(bank,id);
                if (!record) throw std::runtime_error("Missing original SE record");
                for(unsigned c=0;c<record->channels;++c){
                    const auto pcm=kx3::decode_bank_channel(bank,*record,c);
                    const auto bytes=std::span(reinterpret_cast<const std::uint8_t*>(pcm.samples.data()),pcm.samples.size()*2);
                    std::cout<<"{\"id\":"<<id<<",\"channel\":"<<c<<",\"samples\":"<<pcm.samples.size()
                        <<",\"loop_start\":"<<(pcm.loop_start?std::to_string(*pcm.loop_start):"null")
                        <<",\"pcm_sha256\":"<<std::quoted(source_bytes_sha256(bytes))<<"}\n";
                }
            }
            return 0;
        }
        if (argc!=4) throw std::invalid_argument("Usage: cold_story_probe project sn2|sn4|sn4g frame_limit");
        const auto limit=std::stoul(argv[3]);
        if (!limit || limit>100000) throw std::invalid_argument("Invalid frame budget");
        const auto path=std::string_view(argv[1]);
        std::u8string utf8_path(path.begin(),path.end());
        kx3::platform::windows::ProjectGame game(std::filesystem::path(utf8_path),argv[2]);
        const auto& m=game.memory();
        const auto manager=game.runtime().manager, script=m.read_u32(manager+0x38);
        for (unsigned frame=0; frame<limit; ++frame) {
            const auto cursor=m.read_u32(script+0xd8);
            std::cout<<"{\"frame\":"<<frame<<",\"cursor\":"<<cursor
                     <<",\"selector\":"<<m.read_u32(script+0xd0)<<",\"label\":"<<m.read_u32(script+0xd4)
                     <<",\"first_opcode\":"<<unsigned(m.read_u8(cursor));
            try {
                const auto result=game.advance(kx3::ChoiceInput{});
                const auto& pcm=game.last_audio();
                const auto peak=std::accumulate(pcm.begin(),pcm.end(),0,[](int prev,std::int16_t sample){
                    return std::max(prev,std::abs(int(sample)));
                });
                std::cout<<",\"committed\":true,\"steps\":"<<result.script_steps<<",\"glyphs\":"<<result.glyphs.size()
                         <<",\"scene_generation\":"<<game.images().current_generation()
                         <<",\"audio_voices\":"<<game.mixer().voices().size()<<",\"audio_peak\":"<<peak
                         <<",\"timer\":"<<m.read_u32(manager+0x2ec)<<",\"context\":"<<m.read_u32(manager+0x40)
                         <<",\"loader_state\":"<<m.read_u32(0x206250)
                         <<",\"cue_active\":"<<m.read_u32(0x238724)<<",\"cue_write\":"<<m.read_u32(0x23871c)
                         <<",\"cue_read\":"<<m.read_u32(0x238720)<<",\"movie_request\":"<<m.read_u32(0x236268)
                         <<",\"sound_head\":"<<m.read_u32(0x23d3a0)<<",\"sound_tail\":"<<m.read_u32(0x23d3a4)
                         <<",\"pending_effect\":"<<m.read_u32(0x206dd4)<<",\"pending_audio\":"<<m.read_u32(0x238730)
                         <<",\"prepared_generations\":"<<game.images().prepared().size()<<"}\n";
            } catch (const std::exception& e) {
                std::cout<<",\"committed\":false,\"error\":"<<std::quoted(e.what())<<"}\n";
                return 3; // a useful, explicitly incomplete diagnostics result
            }
        }
        return 0;
    } catch (const std::exception& e) { std::cerr<<e.what()<<'\n';return 2; }
}
