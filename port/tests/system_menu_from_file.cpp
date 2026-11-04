#include "../platform/windows/project_game.hpp"
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <string_view>

using kx3::ChoiceInput;
using kx3::SystemMenuAction;
using kx3::platform::windows::ProjectGame;
int main(int argc,char** argv) {
    try {
        if(argc!=4 && argc!=5)throw std::invalid_argument("Pass project, original scenario, a new temporary save path and optionally an existing checkpoint");
        const std::filesystem::path path(argv[3]);
        if(std::filesystem::exists(path))throw std::runtime_error("Refusing to overwrite an existing save for a test");
        auto instance=argc==5?ProjectGame::load(argv[1],argv[2],argv[4]):
            std::make_unique<ProjectGame>(argv[1],argv[2]);
        auto& game=*instance;
        const auto manager=game.runtime().manager;
        auto view=[&]{return kx3::system_menu_view(game.memory(),manager);};
        auto key=[&](std::uint16_t key) {
            ChoiceInput input;input.held=key;
            try { game.advance(input); }
            catch(const std::exception& e) {
                std::cerr<<"tick="<<game.logical_tick()<<" key="<<std::hex<<key
                         <<" context="<<game.memory().read_u32(manager+0x40)
                         <<" menu-open="<<view().open<<" screen="<<view().screen<<std::dec<<'\n';
                throw;
            }
        };
        const auto script=game.memory().read_u32(manager+0x38);
        // Let the retained scene finish its current input delay before polling.
        if(argc==5)for(unsigned i=0;i<121;++i)key(0);
        for(unsigned i=0;!view().open && i<2000;++i) {
            // Physical triangle edges are attempted every other tick. Conditional
            // gates and the gameplay return context are entirely source-controlled.
            if(i%2==0)key(0);else key(0x1000);
        }
        if(!view().open)throw std::runtime_error("The physical button never opened the system menu");
        // Isolate the 19D0F0 conditional from source-menu reachability.
        for(unsigned flags=0;flags<4;++flags){
            kx3::GuestMemory isolated;
            isolated.write_bytes(0,game.memory().bytes(0,kx3::GuestMemory::size));
            isolated.write_u32(0x2388d0,0);
            isolated.write_u32(0x2388d8,flags&1);
            isolated.write_u32(0x2388e0,flags>>1);
            isolated.write_u32(0x2388e8,0);
            kx3::advance_system_menu(isolated,manager,nullptr);
            if(isolated.read_u32(0x2388e8)!=(flags?10u:0u) || isolated.read_u32(0x2388d0)!=1)
                throw std::runtime_error("19D0F0 forced screen disagrees with original branch");
            if(flags){
                isolated.write_u32(0x2388d4,1);
                // Confirm/back must not operate the root menu in original state 10.
                isolated.write_u16(0x1e41c60+0xbc,0x4400);
                kx3::advance_system_menu(isolated,manager,nullptr);
                if(isolated.read_u32(0x2388e8)!=10)
                    throw std::runtime_error("19D0C0 consumed an owner-controlled input");
            }
        }
        const auto opened=game.logical_tick();
        const auto cursor=game.memory().read_u32(script+0xd8);
        const auto object=game.memory().read_u32(manager+0x84c);
        const auto previous=game.memory().read_u32(object+8);
        for(unsigned i=0;i<15;++i)key(0);
        key(0x40);
        if(view().focus!=1)throw std::runtime_error("Original D-pad down did not advance one row");
        key(0);key(0x10);
        if(view().focus!=0)throw std::runtime_error("Original D-pad up did not return to the first row");
        const auto options=view().actions;
        const auto save=std::find(options.begin(),options.end(),SystemMenuAction::SaveAndQuit);
        if(save==options.end())throw std::runtime_error("Source option table omitted Save and Quit");
        ChoiceInput click;click.menu_index=int(save-options.begin());click.menu_confirm=true;
        game.advance(click);
        if(view().screen!=14 || !view().can_request_save)throw std::runtime_error("Original save action did not open confirmation");
        game.save_from_menu(path);
        const auto resumed=ProjectGame::load(argv[1],argv[2],path);
        const auto& memory=resumed->memory();
        if(kx3::system_menu_view(memory,manager).open || memory.read_u32(manager+0x40)!=previous ||
           memory.read_u32(script+0xd8)!=cursor)throw std::runtime_error("Saved context or script cursor mismatched");
        key(0);key(0x4000);key(0);key(0x4000);key(0);
        if(view().open || game.memory().read_u32(manager+0x40)!=previous)
            throw std::runtime_error("Real cancel did not return to the previous context");
        resumed->advance(ChoiceInput{});
        std::cout<<"{\"scenario\":\""<<argv[2]<<"\",\"open_tick\":"<<opened<<",\"story_context\":"<<previous
                 <<",\"source_cursor\":"<<cursor<<",\"save_row\":"<<(save-options.begin())<<",\"passed\":true}\n";
        return 0;
    } catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}
}
