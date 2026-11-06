#include "project_game.hpp"
#include "../../core/staff_roll.hpp"
#include "../snow_layer.hpp"
#include "../../core/depth_particles.hpp"
#include "../sab_layer.hpp"
#include "../mime_layer.hpp"
#include "../screen_transition.hpp"
#include "../screen_slide_layer.hpp"
#include "../../core/screen_wind.hpp"
#include "../../core/screen_wipes.hpp"
#include "../screen_zoom_layer.hpp"
#include "../screen_shake_layer.hpp"
#include "../field_feedback_layer.hpp"
#include "../masked_feedback_layer.hpp"
#include "../screen_ripple_layer.hpp"
#include "../circlemask_layer.hpp"
#include "../screen_mesh_layer.hpp"
#include "../expandband_layer.hpp"
#include "../expandblur_layer.hpp"
#include "../gradefilter_layer.hpp"
#include "../../core/screen_task.hpp"
#include "../../core/recovered.hpp"
#include "../../core/chapter_card_worker.hpp"
#include "../../core/control_transfer.hpp"
#include <algorithm>
#include <bit>
#include <cmath>
#include <sstream>
#include "raster_loader.hpp"
#include "../../core/scene_registry.hpp"
#include "../../core/cue_command.hpp"
#include "../../core/cue_effect.hpp"
#include "../../core/session_clock.hpp"
#include "../../core/scenario_checkpoint.hpp"
#include "../../core/save.hpp"
#include "../../core/save_lock.hpp"
#include <fstream>
#include "../../core/name_entry.hpp"
#include <chrono>
#include <cstdlib>
#include "../../core/audio_worker.hpp"
#include "../../core/system_menu.hpp"
#include "../../core/system_charts.hpp"
#include "../../core/choice_presentation.hpp"
#include <array>

namespace kx3::platform::windows {
namespace {
struct FileIdentity { const char* hash; std::uint32_t size; };
struct Program { std::string_view name; FileIdentity script, font, scenes; };
// Original DISC.FAD entries, also checked against the ISO extraction manifest.
constexpr Program programs[] = {
    {"sn2", {"0c157bd95b8d87d8aae608b671807b392de07af2e3d1a38000bcb735f598f17e",508120},
            {"396d03ea918799696e06495813c0369c8059b18c1ddf1e74b4d1595b4bb84738",879364},
            {"a93814e097498aebc85c934634949c945dfd7c7fd51843247499f47fb8b193fb",160588}},
    {"sn4", {"9313675de61d7034bea8eb42727b4ce0738276ff999da292d4d6b954e9f0114e",728052},
            {"a3dac7e146cc970e4c8ae2c191afa4ffd2592765c0f11e300a66b7ddf12d00c7",1349780},
            {"a2747e5311ec8747acd6e492fa8c055822f98f764ed8704d86397ae9514b32e1",329728}},
    {"sn4g",{"f0a20139375fadff7e5eb7f10c33f1bd503b4e265752a773035f675d99b628f3",1724916},
            {"c12f602b3716b1dce68d6bdbcb58b45dbe29d67dab0a5ef7dbb35210e3d370b3",1098219},
            {"f3424310cebcc0ee374f2b7688ff69f1f06ed466daf2350df80786ce8d3d61f5",801936}}
};
class BootstrapCallbacks final : public ChoiceServices {
public:
    bool supports_source(std::uint32_t) const override { return false; }
    std::uint64_t call_source(GuestMemory&,std::uint32_t,std::span<const std::uint64_t>) override {
        throw std::logic_error("Unresolved source callback during new game construction");
    }
    bool supports_effect(ChoiceEffectKind) const override { return false; }
    bool glyph_animation_pending() const override { throw std::logic_error("Glyph query before font construction"); }
};
}

ProjectGame::ProjectGame(const std::filesystem::path& root,std::string_view scenario,std::optional<std::uint32_t> clock_seed)
    : scenario_(scenario),images_(root),backend_(images_) {
    const Program* selected=nullptr;
    for (const auto& p:programs) if (p.name==scenario) selected=&p;
    if (!selected) throw std::invalid_argument("Unknown original game");
    const auto elf=read_disc_resource(root,"SLPM_664.52",
        "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160",1290132);
    memory_.write_bytes(0x100000,std::span(elf).subspan(0x1000,0x138648));
    // 100548 indexes the original filename table at 204B88 in this order.
    memory_.write_u32(0x235b00,scenario=="sn4"?0u:scenario=="sn4g"?1u:2u);
    struct IconSource{const char* name;const char* sha;unsigned bytes;};
    constexpr IconSource icons[]{
        {"sn4.ico","9ca12f4ffbe79e1c1b5a5097a846dd480a4f6b23aa1427e560a693ea35cc0ec1",62686},
        {"sn4g.ico","e8b164a0b6ddf0058a15da3a73589d0862b9a3f6a46ceb43352a43f9165cda7e",61288},
        {"sn2.ico","640fce76d2d4aea2298b25009cce34e8c21374087828fe0aa11ddb62075a8bbc",64484}
    };
    const auto& icon=icons[memory_.read_u32(0x235b00)];
    card_.set_icon(icon.name,read_disc_resource(root,std::string("ICO/")+icon.name,icon.sha,icon.bytes));
    auto read=[&](const char* suffix,FileIdentity id) {
        return read_disc_resource(root,"SCENARIO/"+std::string(scenario)+suffix,id.hash,id.size);
    };
    std::optional<ReadyScenarioResource> script{{read(".sn4",selected->script),selected->script.size}};
    const auto font=read(".fnt",selected->font);
    const auto scenes=read(".spk",selected->scenes);
    // Slot 2 uses guest reservations outside the manager, script and font arenas.
    const ReadySceneResource scene_slot{0x1000000,0x1000040,0x1100000,0x1200000,0x10000,scenes};
    BootstrapCallbacks callbacks;
    runtime_=bootstrap_manager_dispatch(memory_,script,0x300000,0x400000,0x400000,0x1000000,
                                         callbacks,font,0x1500000,&scene_slot);
    initialize_cue_queue(memory_,5); // Separate from the four manager session locks
    initialize_clock_and_pad(memory_,clock_seed.value_or(static_cast<std::uint32_t>(
        std::chrono::steady_clock::now().time_since_epoch().count())));
    install_system_tables(root);
    install_scenario_checkpoint(memory_);
    // 13BF98: the source reserves two consecutive 640x448 16-bit planes,
    // then clears the whole allocation with a pair of SDs per iteration.
    constexpr std::uint32_t surface=0x1700000;
    memory_.write_u32(0x236114,surface);
    memory_.write_u32(0x236118,surface+0x8c000);
    memory_.write_bytes(surface,std::vector<std::uint8_t>(0x118000));
}

void ProjectGame::install_system_tables(const std::filesystem::path& root) {
    struct CreditFile {const char* hash;unsigned size;};
    constexpr CreditFile files[]={
        {"5ed3a25ccf9692bad1410396e08d4a70ce45ebab0564483a53c8f62487481402",8071},
        {"7bd2031f1d7186d7d5a246c4e51993b55e6cb334bcebd7085c0e58e06f72028f",4021},
        {"064ae82b843dbfc02a8277e6414abeb040bda1eabe262357757d5515d8c18e74",3654}};
    const auto id=memory_.read_u32(0x235b00);
    if(id>=3)throw std::runtime_error("Invalid edition for original staff roll");
    credits::install(memory_,read_disc_resource(root,"STFROLL/"+scenario_+"_stf.txt",files[id].hash,files[id].size),id);
    if(!memory_.read_u32(runtime_.manager+0x34)){
        const auto names=read_disc_resource(root,"SCENARIO/namkan.txt",
            "5bc668b0425b4ff1707a9970f80ca345587c4bdfd3158644ab54210bc5541ec5",4056);
        install_name_entry(memory_,runtime_.manager,names);
    }
    // 10AED0 uploads the five D textures, 10B0A8 uploads the N texture
    // for the three game selectors. Both copy the 128-byte CTF header to
    // 10B290(index). The host renderer gets pixels from the same verified file.
    constexpr FileIdentity effects[]={
        {"1640696c4886e47890bd25651c6f1075ca9cf4c2a05a689e2fc373974ae296fb",8384},
        {"8b33b8b9f3d2853a4bff8eecb53e07da727442e7dd8d2ec189659770e5007570",1408},
        {"1b60fed8bbb7cf6c31e2ab693f166c04ff521cb730e01fcd4b8793bbc604d639",1408},
        {"de880fb6ef343ed2e97358ee8416e6450a057996d954e15b0474693397c2ab12",8384},
        {"b0b84740ca2a246b2c50d94851c850a4b568a068a0e7faadaf16063716e0c952",8384},
        {"30efe2a83cb5b6c694c42e15077225c3e039e67359956844094c8c71d6a0b18c",17536}
    };
    constexpr std::array effect_names={"EFFECT/mark.ctf","EFFECT/blood.ctf","EFFECT/snow.ctf",
                                       "EFFECT/smask.ctf","EFFECT/love.ctf","EFFECT/kakuga.ctf"};
    for(std::uint32_t i=0;i<std::size(effects);++i) {
        const auto record=0x228bb8+i*12,slot=0x23a300+i*128;
        if(memory_.read_u32(slot+112))continue;
        if(memory_.read_u32(record+4)!=i || memory_.read_u8(record)!=(i?'D':'N'))
            throw std::runtime_error("Original effect descriptor table differs at 0x228BB8");
        const auto pointer=memory_.read_u32(record+8);
        const auto chars=memory_.bytes(pointer,32);
        const auto end=std::find(chars.begin(),chars.end(),0);
        if(end==chars.end() || std::string(chars.begin(),end)!=effect_names[i])
            throw std::runtime_error("Original effect resource name differs");
        auto file=read_disc_resource(root,effect_names[i],effects[i].hash,effects[i].size);
        memory_.write_bytes(slot,std::span(file).first(128));
        if(i==2)snow_ctf_=std::move(file);
        if(i==3)circle_ctf_=std::move(file);
    }
    const FileIdentity row=scenario_=="sn2" ? FileIdentity{"19d0c03e35921de96ae16087456ff5af93f242b5b75f4d6eb97edd169e1575a7",410}
        : scenario_=="sn4" ? FileIdentity{"58e55f944053a6d66bc5612590f79638010d91a059d94eab63cfeb045ddec4df",592}
                           : FileIdentity{"562fb366d31c39867096f9b852f4b7e86394921b670db6e3083c7f060c2a64fa",2696};
    if(!memory_.read_u32(0x2381a4)){
        auto entries=read_disc_resource(root,"CHART/"+(scenario_+"_end.dat"),row.hash,row.size);
        install_ending_list(memory_,0x1300000,entries);
    }
    if(scenario_=="sn4g" && !memory_.read_u32(0x2381b8)){
        const auto chart=read_disc_resource(root,"CHART/sn4g_tim.dat",
            "bb53e46ca0622f7abc549c9aee269c885f16f7ddd8ab4c69f22f6344b69377c6",66628);
        install_time_chart(memory_,0x1330000,128*1024,chart);
    }
    if(scenario_!="sn4g" && !memory_.read_u32(0x238208)){
        const bool first=scenario_=="sn2";
        const FileIdentity chapters=first ? FileIdentity{"ef9118b71679e717b310c5f6bd3d9734439e14abdc8bafd40b7faa0955aceb38",2090}
                                          : FileIdentity{"893e7d0f74e43fecd4622513793118e3754ec2619146768ee246e05575a50a2c",1678};
        const auto texture_sha=first?"4c2f3aedee9bb412e6ede002252e7a93b429c2172b4167c0d797663f039df850"
                                    :"16067bacded95d14dcc78da5c13943d998418f0785b7a1872f469c4af9a6956d";
        const auto records=read_disc_resource(root,"CHART/"+(scenario_+"_chap.dat"),chapters.hash,chapters.size);
        const auto textures=read_disc_resource(root,"SYS_MENU/"+(scenario_+"_chtx.dat"),texture_sha,43264);
        install_chapter_list(memory_,{0x1301000,0x1310000,0x1320000},records,textures);
    }
}

FeedbackDraw ProjectGame::text_blur() const {
    const auto pool=memory_.read_u32(0x2388bc);if(!pool)return {};
    for(unsigned i=23;i<=32;++i){const auto task=pool+48*i;
        if(!memory_.read_u32(task) || memory_.read_u32(task+40) || memory_.read_u32(task+24)!=0x17fe70)continue;
        if(memory_.read_u32(task+12)!=2)throw std::runtime_error("Letter-blur lost its two original draw phases");
        (void)draw_captured_blur(memory_,task,0);
        return draw_captured_blur(memory_,task,1);
    }
    return {};
}

std::shared_ptr<const RasterFrame> ProjectGame::scene_frame() const {
    if(composed_tick_==logical_tick_)return composed_scene_;
    const auto source=images_.current_frame();
    std::shared_ptr<RasterFrame> composed;
    const auto overlay=visible_sab(memory_);
    if(source && !overlay.bytes.empty()){
        composed=std::make_shared<RasterFrame>(*source);
        draw_sab_layer(*composed,memory_,overlay);
    }
    const auto table=memory_.read_u32(0x2388bc);
    if(source && table) for(unsigned i=0;i<23;++i) {
        if(i>=10 && i<13)continue; // Mode 1 uses a separate draw phase.
        const auto task=table+48*i;
        if(!memory_.read_u32(task) || memory_.read_u32(task+40))continue;
        const auto pass=memory_.read_u32(task+12), draw=memory_.read_u32(task+24);
        if((pass!=0 && pass!=2) || !draw)continue;
        if(draw==0x183088){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_expandblur_layer(*composed,draw_expandblur(memory_,task));continue;
        }
        if(draw==0x181660){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_gradefilter_layer(*composed,draw_gradefilter(memory_,task));continue;
        }
        if(draw==0x1847a8){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_expandband_layer(*composed,memory_,task);continue;
        }
        if(draw==0x192258){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_screen_transition(*composed,memory_,task);continue;
        }
        if(draw==0x1825b8 || draw==0x182908){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_screen_zoom_layer(*composed,draw_screen_zoom(memory_,task));continue;
        }
        if(draw==0x182188){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_screen_shake_layer(*composed,draw_screen_shake(memory_,task));continue;
        }
        if(draw==0x17e728){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_field_feedback_layer(*composed,memory_,task);continue;
        }
        if(draw==0x181d98){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_screen_ripple_layer(*composed,memory_,task);continue;
        }
        if(draw==0x18a9f0 || draw==0x18aef8 || draw==0x18b408){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_screen_slide_layer(*composed,memory_,task);continue;
        }
        if(draw==0x191168){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_screen_mesh_layer(*composed,memory_,screen_mesh::draw(memory_,task));continue;
        }
        if(draw==0x18f3e8){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            const auto sprites=draw_screen_wind(memory_,task);
            for(unsigned field=0;field<2;++field){
                const auto plane=memory_.read_u32(0x236114+4*field);
                if(!plane)throw std::runtime_error("18F3E8 needs the captured display field");
                const auto saved=memory_.bytes(plane,640*224*4);
                for(const auto& sprite:sprites)draw_field_sprite(*composed,saved,2560,field,sprite.xy,sprite.uv,sprite.alpha);
            }
            continue;
        }
        if(const auto* w=screen_wipe(draw); w && draw==w->draw){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            const auto current=composed->rgba;
            const auto sprites=draw_screen_wipe(memory_,task);
            const auto plane=memory_.read_u32(0x236114);
            if(!plane)throw std::runtime_error("Wipe needs captured display fields");
            for(const auto& sprite:sprites){
                if(sprite.source==WipeSprite::Source::clear){
                    for(std::size_t i=0;i<composed->rgba.size();i+=4)
                        composed->rgba[i]=composed->rgba[i+1]=composed->rgba[i+2]=0;
                    continue;
                }
                const bool saved=sprite.source==WipeSprite::Source::saved;
                for(unsigned field=0;field<2;++field){
                    std::span<const std::uint8_t> pixels=saved?memory_.bytes(plane+field*0x8c000,0x8c000):
                        std::span<const std::uint8_t>(current).subspan(field*2560);
                    draw_field_sprite(*composed,pixels,saved?2560:5120,field,sprite.xy,sprite.uv,sprite.alpha);
                }
            }
            continue;
        }
        if(draw==0x193cb8){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_circlemask_layer(*composed,memory_,circle_ctf_,draw_circlemask(memory_,task));continue;
        }
        if(draw==0x17c698){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_mime_layer(*composed,memory_,task);continue;
        }
        if(draw==0x1836d8){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_snow_particles(*composed,memory_,task,snow_ctf_);
            continue;
        }
        if(draw==0x17f230){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            draw_masked_feedback_layer(*composed,memory_,circle_ctf_,task);continue;
        }
        if(draw==0x183d30){
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            check_particle_texture(*composed,memory_,snow_ctf_);
            for(const auto& p:draw_depth_particles(memory_,task))
                draw_particle_sprite(*composed,snow_ctf_,p.x,p.y,p.size,p.alpha,p.light);
            continue;
        }
        if(draw==0x181110 || draw==0x186da0){
            // 181110 -> 178910 GS MODULATE. The texture is the current color
            // surface and vertex RGB 128 produces the original texel.
            if(!composed)composed=std::make_shared<RasterFrame>(*source);
            const auto data=memory_.read_u32(task+44);
            std::array<int,3> light{};
            for(unsigned c=0;c<3;++c){
                const auto v=draw==0x181110?std::bit_cast<float>(memory_.read_u32(data+24+4*c)):
                    float(std::bit_cast<std::int32_t>(memory_.read_u32(data+12+4*c)))*
                        (std::bit_cast<float>(memory_.read_u32(data))*std::bit_cast<float>(memory_.read_u32(0x237714)));
                if(!std::isfinite(v))throw std::runtime_error("Invalid original effect color");
                light[c]=static_cast<int>(std::clamp(v,0.f,255.f));
            }
            for(std::size_t px=0;px<composed->rgba.size();px+=4)for(unsigned c=0;c<3;++c)
                composed->rgba[px+c]=static_cast<std::uint8_t>(std::min(255,(composed->rgba[px+c]*light[c])>>7));
            continue;
        }
        if(draw!=0x18ea98 && draw!=0x18ee78 && draw!=0x17e3d8){
            std::ostringstream error;
            error<<"Unrecovered source task draw method 0x"<<std::hex<<draw
                 <<" (task 0x"<<task<<")";
            throw std::runtime_error(error.str());
        }
        if(source->width!=640 || source->height!=448)throw std::runtime_error("Source field compositor requires 640x448");
        if(!composed) composed=std::make_shared<RasterFrame>(*source);
        const auto data=memory_.read_u32(task+44);
        // 17E3D8 copies the current field with 176970, then applies FOGCOL
        // (176F78) and the current vertex fog factor through 177FF8.
        const bool fog=draw==0x18ea98 || draw==0x17e3d8;
        const bool snapshot=draw!=0x17e3d8 && (!fog || memory_.read_u32(data)<2);
        const auto factor=std::bit_cast<float>(memory_.read_u32(data+(fog?8:0)));
        if(!std::isfinite(factor))throw std::runtime_error("Invalid source transition factor");
        const int weight=static_cast<int>(std::clamp(factor,0.f,fog?255.f:128.f));
        std::array<int,3> fog_color{};
        if(fog)for(unsigned c=0;c<3;++c)fog_color[c]=memory_.read_u32(data+20+4*c)&255;
        for(unsigned y=0;y<448;++y) {
            // 179DE0 -> 13D040 uses one of the saved 224-line fields.
            // 176970 in phase 2 samples the current scene surface.
            const auto plane=memory_.read_u32(0x236114+4*(y&1));
            const auto captured=memory_.bytes(plane+(y/2)*2560,snapshot?2560:0);
            auto* dst=composed->rgba.data()+y*2560;
            for(unsigned x=0;x<640;++x)for(unsigned c=0;c<3;++c) {
                const int tex=snapshot?captured[x*4+c]:dst[x*4+c];
                const int other=fog?fog_color[c]:dst[x*4+c];
                const int channel=fog?fog_channel(tex,other,weight):source_over_channel(tex,other,weight);
                dst[x*4+c]=static_cast<std::uint8_t>(std::clamp(channel,0,255));
            }
        }
    }
    composed_scene_=composed?std::move(composed):source;
    composed_tick_=logical_tick_;
    return composed_scene_;
}

std::shared_ptr<const RasterFrame> ProjectGame::foreground_frame() const {
    if(foreground_tick_==logical_tick_)return foreground_;
    std::shared_ptr<RasterFrame> overlay;
    const auto table=memory_.read_u32(0x2388bc);
    for(unsigned i=0;table && i<10;++i) {
        const auto task=table+48*i;
        if(!memory_.read_u32(task) || memory_.read_u32(task+40) || memory_.read_u32(task+12)!=1 ||
           memory_.read_u32(task+24)!=0x18ee78)continue;
        const auto weight=std::bit_cast<float>(memory_.read_u32(memory_.read_u32(task+44)));
        if(!std::isfinite(weight) || weight<0 || weight>128)throw std::runtime_error("18EE78 invalid pass-1 alpha");
        if(int(weight)==0)continue;
        const auto alpha=(int(weight)*255+64)/128;
        if(overlay)throw std::runtime_error("Multiple pass-1 18EE78 tasks require ordered GS blending");
        overlay=std::make_shared<RasterFrame>();overlay->width=640;overlay->height=448;
        overlay->rgba.resize(640*448*4);
        for(unsigned y=0;y<448;++y) {
            const auto base=memory_.read_u32(0x236114+4*(y&1));
            const auto scan=memory_.bytes(base+(y/2)*2560,2560);
            auto* out=overlay->rgba.data()+y*2560;
            std::copy(scan.begin(),scan.end(),out);
            for(unsigned x=0;x<640;++x)out[x*4+3]=std::uint8_t(alpha);
        }
    }
    foreground_=std::move(overlay);foreground_tick_=logical_tick_;
    return foreground_;
}

void ProjectGame::set_system_record_file(std::filesystem::path file){
    card_.mount(file.empty()?std::filesystem::path{}:file.parent_path()/"memory-card");
    system_record_file_=std::move(file);
    reconcile_loaded_record();
}

void ProjectGame::export_record(std::span<const std::uint8_t> bank){
    // Continue reads the checkpoint. This second file is a rebuildable copy
    // of the original bank and cannot undo a successful checkpoint replace.
    try{
        std::ifstream existing(system_record_file_,std::ios::binary|std::ios::ate);
        bool matches=false;
        if(existing && existing.tellg()==std::streamoff(bank.size())){
            std::vector<std::uint8_t> bytes(bank.size());
            existing.seekg(0);
            matches=existing.read(reinterpret_cast<char*>(bytes.data()),bytes.size()) &&
                    std::equal(bytes.begin(),bytes.end(),bank.begin());
        }
        existing.close();
        if(!matches)replace_save_file_atomic(system_record_file_,bank);
        record_export_error_.clear();
    }catch(const std::exception& error){record_export_error_=error.what();}
}

void ProjectGame::reconcile_loaded_record(){
    if(autosave_to_original_card_ || system_record_file_.empty() || loaded_checkpoint_.empty() || !memory_.read_u32(0x239fe8) ||
       memory_.read_u32(0x239fa4))return;
    const auto target=memory_.read_u32(0x239fdc),next=memory_.read_u32(0x239fb0),size=memory_.read_u32(0x239e20);
    if(target>=10 || next>1 || size<0x5e0 || size>0x40000)return;
    const auto slot=system_record_file_.parent_path()/(scenario_+"-"+std::to_string(target+1)+".kx3save");
    if(loaded_checkpoint_.lexically_normal()!=slot.lexically_normal())return;
    const auto at=memory_.read_u32(0x235b28+4*(next^1));
    if(at>GuestMemory::size-size)return;
    const auto bank=memory_.bytes(at,size);
    constexpr char magic[]="KMx3-RC01A";
    if(!std::equal(std::begin(magic),std::end(magic),bank.begin()) ||
       memory_.read_u32(at+0x28)!=memory_.read_u32(0x239e28))return;
    try{
        auto lock=system_record_file_;lock+=".lock";
        SaveWriterLock writer(lock,"Save directory is busy");
        // A different session may have replaced this slot since load().
        std::ifstream current(slot,std::ios::binary|std::ios::ate);
        if(!current || current.tellg()<std::streamoff(loaded_checksum_.size()))return;
        current.seekg(-std::streamoff(loaded_checksum_.size()),std::ios::end);
        std::string checksum(loaded_checksum_.size(),'\0');
        if(!current.read(checksum.data(),checksum.size()) || checksum!=loaded_checksum_)return;
        current.close();
        export_record(bank);
    }catch(const std::system_error& error){record_export_error_=error.what();}
}
std::unique_ptr<ProjectGame> ProjectGame::load_note(const std::filesystem::path& root,std::string_view scenario,
                                                  const std::filesystem::path& system_record,unsigned slot){
    if(slot>=10)throw std::invalid_argument("Invalid original card slot");
    auto game=std::make_unique<ProjectGame>(root,scenario);
    game->set_system_record_file(system_record);
    auto& m=game->memory_;
    ExecutionServices services;services.card=&game->card_;services.media=&game->backend_;services.iso_files=&game->images_;
    // 100B98 submits port and slot to 105928. The boot path polls 104CE0
    // before 100A30 hands the restored script selector and label to 112670.
    constexpr std::uint32_t result=0x1357c20;
    bool queued=false,loaded=false;
    for(unsigned tick=0;tick<1200 && !loaded;++tick){
        GuestMemory::AccessBudget budget(m,16'000'000);
        GuestMemory::Transaction tx(m);
        if(!queued)queued=run_scenario_return(m,0x105928,0,slot,&services)!=0;
        advance_card_thread(m,game->card_,0x103ca0);
        advance_card_thread(m,game->card_,0x103640);
        if(queued && !run_scenario_return(m,0x104ce0,result,0,&services)){
            if(m.read_u32(result)!=1)throw std::runtime_error("Original card reader rejected the note");
            loaded=true;
        }
        tx.commit();
    }
    if(!loaded)throw std::runtime_error("Original card reader did not finish");
    game->autosave_to_original_card_=true;
    run_vm_context(m,0x1031c8,0,0,0,0,&services); // 1A57E0 state 2F returns control to the game.
    game->backend_.begin_frame();
    try{
        run_scenario_return(m,0x10c4e8,0,0,&services);
        game->backend_.end_frame(true);
    }catch(...){game->backend_.end_frame(false);throw;}
    return game;
}
std::unique_ptr<ProjectGame> ProjectGame::new_note(const std::filesystem::path& root,std::string_view scenario,
                                                  const std::filesystem::path& system_record,unsigned slot,bool replace){
    if(slot>=10 || system_record.empty())throw std::invalid_argument("Invalid new game card destination");
    if(!replace){
        const auto occupied=note_slots(root,scenario,system_record);
        if(std::find(occupied.begin(),occupied.end(),slot)!=occupied.end())
            throw std::runtime_error("New game memory card slot is already occupied");
    }
    auto game=std::make_unique<ProjectGame>(root,scenario);
    game->set_system_record_file(system_record);
    auto& m=game->memory_;
    ExecutionServices services;services.card=&game->card_;services.media=&game->backend_;services.iso_files=&game->images_;
    constexpr std::uint32_t result=0x1357c20;
    bool queued=false;
    for(unsigned i=0;i<1200;++i){
        GuestMemory::AccessBudget budget(m,16'000'000);
        GuestMemory::Transaction tx(m);
        // Title state 12 creates the note, state 13 polls the write reply.
        if(!queued)queued=run_vm_context(m,0x105538,0,slot,1,0,&services)!=0;
        advance_card_thread(m,game->card_,0x103ca0);
        advance_card_thread(m,game->card_,0x103640);
        const bool done=queued && !run_vm_context(m,0x104c18,result,0,0,0,&services);
        tx.commit();
        if(done){
            if(m.read_u32(result)!=1)throw std::runtime_error("Original memory card rejected the new game record");
            run_vm_context(m,0x1031c8,0,0,0,0,&services); // 1A4D40 state 2F selects card mode 5 for a bound port.
            game->card_.commit_writes(!replace);
            game->autosave_to_original_card_=true;
            return game;
        }
    }
    throw std::runtime_error("Original new game card write did not finish");
}
std::vector<unsigned> ProjectGame::note_slots(const std::filesystem::path& root,std::string_view scenario,
                                             const std::filesystem::path& system_record){
    if(!std::filesystem::exists(system_record.parent_path()/"memory-card/card.bin"))return {};
    ProjectGame preview(root,scenario,4357u);
    preview.set_system_record_file(system_record);
    auto& m=preview.memory_;
    ExecutionServices services;services.card=&preview.card_;services.iso_files=&preview.images_;
    constexpr std::uint32_t directory=0x1e4adb0; // Original buffer used by 1A44D8.
    for(unsigned i=0;i<180;++i){
        GuestMemory::AccessBudget budget(m,16'000'000);
        GuestMemory::Transaction tx(m);
        run_scenario_return(m,0x107518,directory,0,&services);
        advance_card_thread(m,preview.card_,0x103640);
        tx.commit();
        if(m.read_u32(directory)!=1)continue;
        std::vector<unsigned> slots;
        // 1AA508 accepts type 1 for load. Types 3 and 4 are displayed
        // as damaged and rejected by 1AAD40 on the load screen.
        for(unsigned slot=0;slot<10;++slot)if(m.read_u32(directory+36+4*slot)==1)slots.push_back(slot);
        return slots;
    }
    throw std::runtime_error("Original memory card scan did not finish");
}

void ProjectGame::enter_label_for_probe(std::uint32_t selector,std::uint32_t name_file_offset) {
    if(logical_tick_ || frame_complete_)throw std::logic_error("Direct entry requires a fresh diagnostic session");
    const auto script=memory_.read_u32(runtime_.manager+0x38);
    GuestMemory::Transaction tx(memory_);
    invoke_recovered(memory_,0x10db48,script,selector,memory_.read_u32(script+4)+name_file_offset);
    tx.commit();
}
void ProjectGame::enter_record_for_probe(std::uint32_t selector,std::uint32_t file_offset){
    if(logical_tick_ || frame_complete_ || selector>=32)throw std::logic_error("Record probe requires a fresh session");
    const auto script=memory_.read_u32(runtime_.manager+0x38);
    const auto block=memory_.read_u32(script+8+4*selector),addr=memory_.read_u32(script+4)+file_offset;
    if(!block || addr<memory_.read_u32(block+0x430))throw std::invalid_argument("Bad record offset");
    GuestMemory::Transaction tx(memory_);
    invoke_recovered(memory_,0x10d830,script,selector,addr-memory_.read_u32(block+0x430));
    tx.commit();
}
void ProjectGame::prepare_choice_layout_for_probe(){
    // Each program's opening block sets the same eight font preferences.
    // A direct 6C entry bypasses them, leaving the wrap boundary at zero.
    const unsigned offset=scenario_=="sn2"?0x4cf3:scenario_=="sn4"?0x6adb:0xe26;
    enter_record_for_probe(0,offset);
    GuestMemory::Transaction tx(memory_);
    const auto owner=runtime_.manager,script=memory_.read_u32(owner+0x38);
    const auto context=memory_.read_u32(owner+0x40);
    if(context!=memory_.read_u32(0x235f3c))throw std::runtime_error("Expected original default context");
    for(unsigned op:{0x5eu,0x60u,0x62u,0x64u,0x54u,0x56u,0x45u,0x41u}){
        if(memory_.read_u8(memory_.read_u32(script+0xd8))!=op)
            throw std::runtime_error("Original opening font preference record differs");
        invoke_recovered(memory_,0x120308,context,owner);
    }
    invoke_recovered(memory_,0x12f1d0,0); // 12F914, apply the page's retained preferences.
    tx.commit();
}
void ProjectGame::enter_staff_roll_for_probe(){
    if(logical_tick_ || frame_complete_)throw std::logic_error("Direct credit entry requires a fresh diagnostic session");
    const auto program=std::find_if(std::begin(programs),std::end(programs),[&](const auto& p){return p.name==scenario_;});
    if(program==std::end(programs))throw std::logic_error("Unknown staff program");
    constexpr unsigned base=0x1100000;
    const auto spk=memory_.bytes(base,program->scenes.size);
    constexpr char command[]="\x23\x00\x2a\x00oya staffroll_start";
    const auto start=std::search(spk.begin(),spk.end(),command,command+sizeof(command));
    if(start==spk.end())throw std::runtime_error("Missing retail AT staffroll_start in resident SPK");
    GuestMemory::Transaction tx(memory_);
    memory_.write_u32(0x238724,base+static_cast<unsigned>(start-spk.begin()));
    ExecutionServices services;services.media=&backend_;services.sound_device=&mixer_;services.iso_files=&images_;
    invoke_cue_command(memory_,0x1397d8,0,0,0,&services);
    if(!memory_.read_u32(0x236828))throw std::runtime_error("Original AT command did not start credits");
    tx.commit();
}

TitleAction ProjectGame::title_input(TitleSelection& title,std::uint16_t buttons,std::vector<SourceSoundEvent>& sounds){
    SystemMenuHost host{0,[&](std::uint32_t id)->const SoundRecord*{
        const auto sound=images_.sound_for_play(id);
        return sound?&sound->record:nullptr;
    }};
    ExecutionServices services;services.system_menu=&host;services.system_sounds=&sounds;
    return advance_title_selection(memory_,title,buttons,services);
}
StoryFrameResult ProjectGame::advance(std::optional<ChoiceInput> input) {
    // The loader runs independently of script yield. Its resources and guest
    // effects commit together before the manager starts its own transaction.
    if(!workers_done_){
        // A published original bank remains retryable until its host I/O
        // succeeds. Manual story slots are independent of this system file.
        if(!autosave_to_original_card_ && memory_.read_u32(0x239fe8) && memory_.read_u32(0x239fa4)==1){
            const auto slot=memory_.read_u32(0x239fb0),bytes=memory_.read_u32(0x239e20);
            if(slot>1 || bytes<0x5e0 || bytes>0x40000)throw std::runtime_error("Invalid source system record");
            const auto image=memory_.bytes(memory_.read_u32(0x235b28+4*slot),bytes);
            std::vector<std::uint8_t> committed(image.begin(),image.end());
            std::optional<SaveWriterLock> writer;
            if(!system_record_file_.empty()){
                std::filesystem::create_directories(system_record_file_.parent_path());
                const auto target=memory_.read_u32(0x239fdc);
                if(target>=10)throw std::runtime_error("Source auto-save slot is out of bounds");
                const auto destination=system_record_file_.parent_path()/(scenario_+"-"+std::to_string(target+1)+".kx3save");
                auto lock=system_record_file_;lock+=".lock";
                writer.emplace(lock,"Save directory is busy");
                save_impl(destination,false,std::nullopt,true);
            }
            last_system_record_=std::move(committed); // Also used by standalone memory-backed test sessions.
            memory_.write_u32(0x239fa0,0);memory_.write_u32(0x239fa4,0);
            memory_.write_u32(0x239fb0,(slot+1)%2); // 1032B8 after a successful device write.
            if(writer)export_record(last_system_record_);
        }
        frame_complete_=false;
        GuestMemory::AccessBudget budget(memory_,16'000'000);
        GuestMemory::Transaction tx(memory_);
        backend_.begin_frame();
        try {
            // 135108 -> 13CEB0 snapshots the pending count before 137D78.
            // 13D098 observes this one-update lag even after the final field.
            memory_.write_u32(0x236110,memory_.read_u32(0x236104));
            if(autosave_to_original_card_ && memory_.read_u32(0x239fe8) && memory_.read_u32(0x239fa4)==1){
                // 1032B8 advances the timer, submits command 4 via 1049F0 and
                // rotates the source bank only after the original queue accepts.
                ExecutionServices card_services;card_services.card=&card_;
                run_vm_context(memory_,0x1032b8,0,0,0,0,&card_services);
            }else advance_record_timer(memory_);
            advance_card_thread(memory_,card_,0x103ca0); // priority 19
            advance_card_thread(memory_,card_,0x103640); // priority 20
            const auto events=service_audio_worker(memory_,[&](std::uint32_t id)->const SoundRecord* {
                const auto sound=images_.sound_for_play(id);
                return sound ? &sound->record : nullptr;
            });
            ProjectMixer next=mixer_;
            next.apply(events,images_);
            tick_deferred_scene(memory_,backend_);
            ExecutionServices workers;workers.screen_task_heap=0x1000200;workers.sound_device=&next;workers.media=&backend_;workers.iso_files=&images_;
            advance_scene_fade(memory_,&workers);
            memory_.write_u32(0x20625c,memory_.read_u32(0x20625c)+1); // 135230..135240.
            tick_screen_tasks(memory_,0x1000200); // Native 17A560 private area outside the SPK registry.
            tick_cue_effects(memory_,workers.screen_task_heap,&workers);
            if(memory_.read_u32(0x238724) || memory_.read_u32(0x23871c)!=memory_.read_u32(0x238720) ||
               memory_.read_u32(0x206dcc)!=memory_.read_u32(0x206dd0)){
                memory_.write_u32(0x206dc8,memory_.read_u32(0x206dc8)+1); // 1353B0..C4
                invoke_cue_command(memory_,0x1395a8,0,0,0,&workers);
            }
            advance_sab_draw(memory_); // 1354FC precedes both display readbacks.
            credits::advance(memory_,&workers); // 100A88, after the original effect update.
            composed_tick_=UINT64_MAX; // The native UI may already have drawn this logical tick before its workers ran.
            const auto display_field=unsigned(logical_tick_&1); // 151550 returns the physical 60 Hz display field.
            capture_source_display_field(memory_,0,display_field,[&](auto dest,auto field) {
                images_.image_presenter()->capture_field(memory_,dest,field); // 13553C or 135570, earlier scene pass.
            });
            capture_source_display_field(memory_,1,display_field,[&](auto dest,auto field) {
                const auto picture=scene_frame(); // 13D33C late pass uses the committed game scene.
                if(!picture || picture->width!=640 || picture->height!=448 || picture->rgba.size()!=640*448*4)
                    throw std::runtime_error("13D310 needs a committed 640x448 presentation");
                const auto bytes=std::span(picture->rgba);
                for(unsigned y=0;y<224;++y)memory_.write_bytes(dest+y*2560,bytes.subspan((2*y+field)*2560,2560));
            });
            const auto selected=images_.prepared().find(backend_.selected_scene_generation());
            const auto film=selected!=images_.prepared().end() && memory_.read_u32(0x236268) ?
                selected->second.movie.get():nullptr;
            auto samples=next.mix_tick(film,backend_.movie_position());
            card_.commit_writes();
            tx.commit();
            mixer_=std::move(next);
            audio_block_=samples;
        } catch (...) { card_.discard_writes();composed_tick_=UINT64_MAX;backend_.end_frame(false); throw; }
        backend_.end_frame(true);
        workers_done_=true;
    }
    SystemMenuHost menu{runtime_.manager_arena_used_end,[&](std::uint32_t id)->const SoundRecord*{
        const auto sound=images_.sound_for_play(id);
        return sound?&sound->record:nullptr;
    }};
    if(menu.context_storage+4>0x400000)throw std::runtime_error("No cold heap space for system menu context");
    if(!pending_manager_frame_){
        const bool polling_card=input && input->original_card_menu && memory_.read_u32(0x2388e8)==12 &&
                                memory_.read_u32(0x2380d0)==19;
        pending_manager_frame_=driver_.advance(memory_,runtime_.manager,&backend_,nullptr,input,&menu,0x1000200,&mixer_,&images_);
        if(polling_card && memory_.read_u32(0x2380d0)==20)autosave_to_original_card_=true;
    }
    auto& pending=*pending_manager_frame_;
    std::optional<ProjectMixer> after_menu;
    if(!pending.system_sounds.empty()){
        after_menu=mixer_;after_menu->apply(pending.system_sounds,images_);
    }
    const auto first=pending.last_page_clear.value_or(0);
    const auto kept=pending.last_page_clear?0:visible_text_.size();
    visible_text_.reserve(kept+pending.glyphs.size()-first);
    advance_source_glyphs(memory_,memory_.read_u32(runtime_.manager+0x3c));
    if(after_menu)mixer_=std::move(*after_menu);
    if(pending.last_page_clear)visible_text_.clear();
    visible_text_.insert(visible_text_.end(),pending.glyphs.begin()+first,pending.glyphs.end());
    auto result=std::move(pending);
    pending_manager_frame_.reset();workers_done_=false;
    ++logical_tick_;frame_complete_=true;
    // Submit a given logical tick only once, after every retryable stage.
    output_submit_us_=0;
    if(audio_enabled_) {
        static const bool measure=std::getenv("KX3_FRAME_TRACE")!=nullptr;
        const auto started=measure?std::chrono::steady_clock::now():std::chrono::steady_clock::time_point{};
        try {
            if(!output_ && (!mixer_.voices().empty() || mixer_.music() ||
               std::any_of(audio_block_.begin(),audio_block_.end(),[](auto s){return s!=0;})))output_=std::make_unique<WaveOutput>();
            if(output_)output_->submit(audio_block_);
        } catch(const std::exception& error) {
            // E.g. device removal or a remote desktop without an audio endpoint.
            // The game clock and source audio state stay valid for a later retry.
            audio_error_=error.what();output_.reset();audio_enabled_=false;
        }
        if(measure)output_submit_us_=std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now()-started).count();
    }
    return result;
}
}
