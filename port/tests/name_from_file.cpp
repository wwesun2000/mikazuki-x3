#include "../platform/windows/project_game.hpp"
#include "../core/name_entry.hpp"
#include <iostream>
#include <stdexcept>
using kx3::ChoiceInput;
using kx3::platform::windows::ProjectGame;
int main(int argc,char** argv){
    try{
        if(argc<2 || argc>3)throw std::invalid_argument("Pass the original project root and optional scenario");
        const std::string scenario=argc==3?argv[2]:"sn2";
        ProjectGame game(argv[1],scenario);
        auto& m=game.memory();const auto mgr=game.runtime().manager;
        auto view=[&]{return kx3::name_entry_view(m,mgr);};
        auto input=[&](ChoiceInput i){
            try {game.advance(i);}
            catch(const std::exception& e){
                std::cerr<<"tick="<<game.logical_tick()<<" open="<<view().open<<" held="<<i.held<<'\n';throw;
            }
        };
        auto key=[&](std::uint16_t held){input(ChoiceInput{.held=held});};
        auto tap=[&](std::uint16_t button){key(0);key(button);key(0);};
        std::array<unsigned,2> opened{};
        for(unsigned which=0;which<2;++which){
            while(!view().open && game.logical_tick()<3000){
                key(0);const auto ctx=m.read_u32(mgr+0x40);
                if(ctx==m.read_u32(0x235f34) || ctx==m.read_u32(0x235f38))tap(0x2000);
            }
            if(!view().open || view().slot!=which)throw std::runtime_error("Expected original name entry did not open");
            opened[which]=unsigned(game.logical_tick());
            const auto original=view().draft_cp932;
            if(original.empty())throw std::runtime_error("Missing original default name");
            tap(0x20);
            if(view().focus==0)throw std::runtime_error("Original D-pad did not move focus");
            const auto before=view();
            const auto target=std::find_if(before.cells.begin(),before.cells.end(),[](const auto& c){return c.source_kind=='N';});
            if(target==before.cells.end())throw std::runtime_error("No source character in first grid");
            input(ChoiceInput{.name_index=int(target->index),.name_confirm=true});
            if(view().draft_cp932!=original+target->text_cp932)throw std::runtime_error("Pointer did not insert selected source character");
            tap(0x4000);
            if(view().draft_cp932!=original)throw std::runtime_error("Original delete did not restore default name");
            tap(0x1000);
            if(!view().confirming || view().confirm_focus!=1)throw std::runtime_error("Name confirmation did not default to No");
            tap(0x10);
            if(!view().confirming || view().confirm_focus!=0)throw std::runtime_error("Original Yes/No did not move to Yes");
            tap(0x2000);
            if(view().open)throw std::runtime_error("Original accepted name did not return to the story");
            std::cout<<"{\"source_name_slot\":"<<which<<",\"opened\":"<<opened[which]
                     <<",\"returned\":"<<game.logical_tick()<<"}\n";
        }
        std::cout<<"{\"scenario\":\""<<scenario<<"\",\"first_name_tick\":"<<opened[0]<<",\"second_name_tick\":"<<opened[1]
                 <<",\"returned_tick\":"<<game.logical_tick()<<",\"passed\":true}\n";return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}
}
