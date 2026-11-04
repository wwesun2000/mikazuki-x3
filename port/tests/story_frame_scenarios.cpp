#include "story_frame_scenarios.hpp"
#include "../core/choice_presentation.hpp"
#include "../core/media_active.hpp"
#include "../core/story_frame.hpp"
#include "../core/recovered.hpp"
#include "../core/save.hpp"
#include "../platform/text_layer.hpp"
#include "../platform/windows/project_media.hpp"
#include <iostream>
#include <iomanip>
#include <charconv>

namespace kx3::tests {
namespace {
using u32=std::uint32_t;
void require(bool condition,const char* message){if(!condition)throw std::runtime_error(message);}
std::array<std::uint8_t,32> source_digest(std::string_view hex) {
    std::array<std::uint8_t,32> digest{};
    require(hex.size()==64,"Invalid source fingerprint length");
    for(unsigned i=0;i<32;++i) {
        unsigned b=0;
        const auto* first=hex.data()+2*i;
        const auto parsed=std::from_chars(first,first+2,b,16);
        require(parsed.ec==std::errc{} && parsed.ptr==first+2,"Invalid source fingerprint");
        digest[i]=std::uint8_t(b);
    }
    return digest;
}
void choice_scene(GuestMemory& m,u32 manager,MediaCommandBackend& media,bool mouse,u32 option) {
    const auto choice=m.read_u32(manager+8),font=m.read_u32(manager+0x3c),script=m.read_u32(manager+0x38);
    const auto pool=m.read_u32(m.read_u32(font+8));
    const auto node=m.read_u32(pool+8)+56*m.read_u32(choice+0xc8+4*option);
    const int x=int(m.read_u32(node+12))+1,y=int(m.read_u32(node+16))+1;
    const auto hit=source_choice_at(m,manager,x,y);
    require(hit && *hit==option && !source_choice_at(m,manager,639,447),"Source hit regions disagree with visible option");
    StoryFrameDriver driver;
    auto go=[&](ChoiceInput input) {
        auto frame=driver.advance(m,manager,&media,nullptr,input);
        advance_source_glyphs(m,font);
        return frame;
    };
    ChoiceInput select;
    if(mouse){select.mouse_index=int(*hit);go(select);}
    else {
        select.held=0x40;
        for(u32 i=0;i<option;++i){go(select);go({});}
    }
    require(m.read_u32(choice+0x168)==option,"Original input focused the wrong answer");
    require(m.read_u8(node)==128 && m.read_u8(node+1)==64 && m.read_u8(node+2)==64,"Source focus color not applied to answer");
    go({});
    ChoiceInput confirm;
    if(mouse){confirm.mouse_index=int(*hit);confirm.mouse_confirm=true;}else confirm.held=0x2000;
    go(confirm);
    const auto confirmation=m.read_u32(manager+0x40);
    unsigned frames=0;
    while(m.read_u32(manager+0x40)==confirmation && frames<24){go({});++frames;}
    const auto label=m.read_u32(script+0xd4);
    const auto name=u32(invoke_recovered(m,0x10fa68,script,label));
    std::string text;
    for(unsigned i=0;i<64 && m.read_u8(name+i);++i)text+=char(m.read_u8(name+i));
    constexpr const char* targets[]{"rxb01_0410","rx01_0462","rxb01_0470"};
    require(text==targets[option] && m.read_u32(script+0xd0)==(option==1?18u:19u),"Choice did not reach its original label");
    std::cout<<"{\"check\":\"choice_transfer\",\"device\":"<<std::quoted(mouse?"mouse":"keyboard")
             <<",\"option\":"<<option<<",\"hit_x\":"<<x<<",\"hit_y\":"<<y<<",\"frames_after_confirm\":"<<frames
             <<",\"source_target\":"<<std::quoted(text)<<"}\n";
}
}
void run_story_frames(GuestMemory& m,const std::filesystem::path& root,bool choice,const std::filesystem::path& test_save) {
    const u32 manager=m.read_u32(0x235e40),script=m.read_u32(manager+0x38),font=m.read_u32(manager+0x3c);
    platform::windows::ProjectImageServices images(root);
    SourceMediaActiveBackend media(images);
    const auto ram=m.bytes(0,GuestMemory::size);
    std::vector<std::uint8_t> original(ram.begin(),ram.end());
    if(choice) {
        for(u32 option=0;option<3;++option)for(bool mouse:{true,false}){
            m.write_bytes(0,original);
            choice_scene(m,manager,media,mouse,option);
        }
        return;
    }
    StoryFrameDriver driver;
    const auto resume_cursor=m.read_u32(script+0xd8);
    const auto initial_timer=m.read_u32(manager+0x2ec);
    require(initial_timer==13,"Unexpected initial slot4 timer");
    for(unsigned left=initial_timer;left>1;--left){
        auto frame=driver.advance(m,manager,&media);
        require(frame.timer_pending && !frame.script_steps && m.read_u32(script+0xd8)==resume_cursor
            && m.read_u32(manager+0x2ec)==left-1,"Restored wait changed the script cursor");
    }
    std::cout<<"{\"check\":\"restored_timer\",\"initial\":13,\"held_frames\":12}\n";
    const auto handler=m.read_u32(manager+0x5c+0x65*4);
    const auto target=m.read_u32(handler)+0x3c,original_target=m.read_u32(target);
    m.write_u32(target,0xdead1234); // Fault after the real image preload in this frame.
    std::copy(ram.begin(),ram.end(),original.begin());
    bool rejected=false;
    try{(void)driver.advance(m,manager,&media);}
    catch(const std::exception& error){
        if(std::string(error.what()).find("dead1234")==std::string::npos)throw;
        rejected=true;
    }
    require(rejected && images.prepared().empty() && images.next_generation()==1 &&
            std::equal(original.begin(),original.end(),ram.begin()),
            "Failed multi-command frame retained partial RAM or assets");
    m.write_u32(target,original_target);
    std::cout<<"{\"check\":\"post_preload_frame_rollback\",\"passed\":true}\n";
    auto first=driver.advance(m,manager,&media);
    require(first.script_steps==69 && first.glyphs.size()==48 && m.read_u32(manager+0x2ec)==90,"First frame did not reach the original 90-tick wait");
    const auto waiting=m.read_u32(script+0xd8);
    const auto layer=platform::render_text_layer(m,font);
    require(std::any_of(layer.rgba.begin(),layer.rgba.end(),[](auto v){return v!=0;}),"Missing visible text at first yield");
    for(unsigned i=1;i<90;++i) {
        auto frame=driver.advance(m,manager,&media);
        require(frame.timer_pending && frame.script_steps==0 && m.read_u32(manager+0x2ec)==90-i
                && m.read_u32(script+0xd8)==waiting,"Cursor or timer drifted inside original wait");
        advance_source_glyphs(m,font);
        if(i==45) {
            CoreCheckpoint saved;
            saved.memory.write_bytes(0,ram);saved.manager=manager;saved.logical_tick=initial_timer+i;
            SaveIdentity identity{};
            identity.executable_sha256=source_digest("50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160");
            identity.assets_sha256=source_digest("2a193cdbe97ba96faf0ad4d376a1d45b765aa99625895ff161f5102a5e85c95d");
            identity.core_abi_revision=0x20261031;
            write_checkpoint_atomic(test_save,saved,identity);
            auto loaded=read_checkpoint(test_save,identity);
            require(loaded.manager==manager && loaded.logical_tick==saved.logical_tick
                    && std::equal(ram.begin(),ram.end(),loaded.memory.bytes(0,ram.size()).begin()),"Persisted mid-wait state differs");
            require(platform::render_text_layer(loaded.memory,font).rgba==platform::render_text_layer(m,font).rgba,
                    "Restored source text pixels differ");
            StoryFrameDriver resumed;
            const auto next=resumed.advance(loaded.memory,manager,nullptr);
            require(next.timer_pending && next.script_steps==0 && loaded.memory.read_u32(manager+0x2ec)==44
                    && loaded.memory.read_u32(script+0xd8)==waiting,"Restored wait did not resume at the next original tick");
            std::cout<<"{\"check\":\"disk_save_resume\",\"timer_saved\":45,\"timer_next\":44,\"whole_ram_equal\":true,\"text_layer_equal\":true}\n";
        }
    }
    std::cout<<"{\"check\":\"story_timed_wait\",\"script_steps\":69,\"glyphs\":48,\"wait\":90,\"held_frames_verified\":89}\n";
    require(m.read_u8(waiting)==0x0c,"Unexpected source page command after timer");
    const auto resumed=driver.advance(m,manager,&media);
    require(resumed.script_steps==1 && m.read_u32(manager+0x2ec)==0 && m.read_u8(m.read_u32(script+0xd8))==0x85,
            "Post-wait source page close did not yield at the real transfer");
    std::cout<<"{\"check\":\"resume_after_wait\",\"result\":\"page_closed\",\"steps\":1,\"next_opcode\":133}\n";
    const auto before_transfer=m.read_u32(script+0xd8);
    const auto frame=driver.advance(m,manager,&media);
    require(frame.script_steps==7 && m.read_u32(script+0xd8)!=before_transfer,
            "Original slot4 page transfer no longer reaches its next yield");
    std::cout<<"{\"check\":\"post_transfer_frame\",\"result\":\"returned\",\"steps\":"<<frame.script_steps<<"}\n";
}
}
