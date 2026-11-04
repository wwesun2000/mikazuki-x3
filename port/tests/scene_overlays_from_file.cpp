#include "../platform/windows/project_game.hpp"
#include "../platform/windows/scene_surface.hpp"
#include "../platform/windows/window_drawing.hpp"
#include "../platform/sab_layer.hpp"
#include "../core/cue_command.hpp"
#include "../core/cue_effect.hpp"
#include "../core/mime_effect.hpp"
#include <iomanip>
#include <fstream>

namespace {
void capture_scene(const kx3::platform::RasterFrame& image,const std::filesystem::path& filename){
    using namespace kx3::platform::windows;
    if(FAILED(CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED)))throw std::runtime_error("WIC capture needs COM");
    struct ComSession {~ComSession(){CoUninitialize();}} com;
    std::vector<std::uint32_t> pixels;pixels.reserve(image.rgba.size()/4);
    for(unsigned y=0;y<448;++y)for(unsigned x=0;x<640;++x)
        pixels.push_back(scene_pixel(image.rgba.data()+4*(640*y+x),y,false));
    const auto instance=GetModuleHandleW(nullptr);WNDCLASSW wc{};
    wc.hInstance=instance;wc.lpszClassName=L"KX3OriginalSceneProbe";
    wc.lpfnWndProc=[](HWND w,UINT msg,WPARAM wp,LPARAM lp)->LRESULT{
        if(msg==WM_NCCREATE)SetWindowLongPtrW(w,GWLP_USERDATA,LONG_PTR(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams));
        if(msg==WM_PRINTCLIENT){
            const auto* src=reinterpret_cast<const std::uint32_t*>(GetWindowLongPtrW(w,GWLP_USERDATA));
            RECT rect{};GetClientRect(w,&rect);draw_scene_surface(HDC(wp),rect,640,448,src,false);return 0;
        }
        return DefWindowProcW(w,msg,wp,lp);
    };
    if(!RegisterClassW(&wc))throw std::runtime_error("Could not register source scene window");
    const auto w=CreateWindowExW(0,wc.lpszClassName,L"",WS_POPUP,0,0,640,448,nullptr,nullptr,instance,pixels.data());
    if(!w){UnregisterClassW(wc.lpszClassName,instance);throw std::runtime_error("Could not create native scene window");}
    try{(void)capture_window_client(w,filename,false);}
    catch(...){DestroyWindow(w);UnregisterClassW(wc.lpszClassName,instance);throw;}
    DestroyWindow(w);UnregisterClassW(wc.lpszClassName,instance);
}
}
#include <iostream>

// Isolated source subsystem test. The constructor reads SN4 from disk. Test
// scene names enter at original 101B58, independently of story progression.
int main(int argc,char** argv){
    using namespace kx3;
    using namespace kx3::platform::windows;
    try {
        if(argc!=2 && argc!=3)return 2;
        const std::filesystem::path root=argv[1];
        ProjectGame cold(root,"sn4",19);
        if(argc==3 && std::string_view(argv[2])=="--mime-factory"){
            // The two allocation ABI calls in the R5900 fixture return these
            // same reserved guest addresses. The original RNG state is retained.
            std::ifstream file(root/"local/ghidra-oracle-inputs/choice-slot7-ee.bin",std::ios::binary);
            std::vector<std::uint8_t> fixture(GuestMemory::size);
            if(!file.read(reinterpret_cast<char*>(fixture.data()),fixture.size()) || file.peek()!=EOF)
                throw std::runtime_error("Missing exact EE fixture");
            const std::array<std::array<std::uint32_t,5>,2> args{{{0,80,80,80,700},{40,150,25,15,300}}};
            for(const auto& a:args){
                GuestMemory m;m.write_bytes(0,fixture);
                const auto expected=m.read_u32(0x2388bc)+13*48;
                const std::array<std::uint8_t,48> empty{};m.write_bytes(expected,empty);
                m.write_bytes(0x1410000,std::vector<std::uint8_t>(3728,0xa5));
                m.write_u32(0x20c7d0,17);m.write_u32(0x20c7d4,UINT32_MAX);
                m.write_u32(0x20c7d8,0);m.write_u32(0x20c7dc,0);
                const auto task=create_mime_effect(m,a,nullptr);
                if(task!=expected)throw std::runtime_error("Original mode-zero slot differs");
                for(auto region:{m.bytes(task,48),m.bytes(0x1410000,3728),m.bytes(0x1e497e8,624*4)})
                    for(auto v:region)std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(v);
                std::cout<<'\n';
            }
            return 0;
        }
        if(argc==3 && std::string_view(argv[2])=="--flash"){
            const std::array<std::array<int,6>,4> params{{{0,0,0,255,0,0},{4,3,10,7,8,9},
                {0,3,-4,12,16,255},{7,0,-16,32,128,9}}};
            for(const auto& args:params){
                GuestMemory m;m.write_bytes(0,cold.memory().bytes(0,GuestMemory::size));
                constexpr std::uint32_t blob=0x10fd000;
                auto big=[&](auto p,std::uint32_t v){for(int j=0;j<4;++j)m.write_u8(p+j,std::uint8_t(v>>(24-j*8)));};
                big(blob,5);m.write_u8(blob+4,6);
                for(int i=0;i<6;++i)big(blob+5+i*4,std::uint32_t(args[i]));
                ExecutionServices host;host.screen_task_heap=0x1000200;
                cue_effect_on(m,cold.runtime().manager,blob,29,&host);
                const auto task=m.read_u32(0x2388bc)+13*48;
                for(auto region:{m.bytes(task,48),m.bytes(m.read_u32(task+44),48)})
                    for(auto v:region)std::cout<<std::hex<<std::setw(2)<<std::setfill('0')<<unsigned(v);
                std::cout<<'\n';
            }
            return 0;
        }
        for(const auto& [scene,cue]:{std::pair{"my0006","my0006_00"},{"my0005","my0005_99"},
                    {"my0034","my0034_10"},{"myb0036","myb0036_15"},{"my0033","my0033_00"}}){
            GuestMemory m;m.write_bytes(0,cold.memory().bytes(0,GuestMemory::size));
            ProjectImageServices images(root);SourceMediaActiveBackend media(images);
            constexpr std::uint32_t scratch=0x10fd000;
            auto write_name=[&](std::uint32_t addr,const char* label){
                auto len=std::char_traits<char>::length(label);
                m.write_bytes(addr,{reinterpret_cast<const std::uint8_t*>(label),len+1});
            };
            write_name(scratch,scene);write_name(scratch+32,cue);
            auto provider=m.read_u32(0x235efc),registry=m.read_u32(provider+4);
            if(!invoke_media_command(m,0x101b58,registry,scratch+64,scratch+68,scratch))
                throw std::runtime_error("Original scene registry lookup failed");
            (void)invoke_media_command(m,0x137578,m.read_u32(scratch+68),scratch,0,0,0x23daf0,&media);
            for(unsigned tick=0;tick<32 && !media.selected_scene_generation();++tick){
                GuestMemory::Transaction tx(m);media.begin_frame();
                try{
                    tick_deferred_scene(m,media);
                    if(m.read_u32(0x206250)==8)media.finish_deferred(m);
                    tx.commit();media.end_frame(true);
                }catch(...){media.end_frame(false);throw;}
            }
            const auto& group=images.prepared().at(media.selected_scene_generation());
            const auto program=invoke_cue_command(m,0x101ca8,registry,m.read_u32(scratch+64),scratch+32,nullptr);
            if(!program)throw std::runtime_error("Original cue registry lookup failed");
            invoke_cue_command(m,0x138e10,std::uint32_t(program),scratch+32,0,nullptr);
            advance_sab_draw(m);
            auto visible=visible_sab(m);
            if(group.animations.empty()!=visible.bytes.empty())throw std::runtime_error("Scene cue did not activate its original SAB");
            unsigned changed=0;
            if(!visible.bytes.empty()){
                const auto& source=*group.frames.at(group.plan.primary_virtual_name);
                auto result=source;platform::draw_sab_layer(result,m,visible);
                for(std::size_t i=0;i<result.rgba.size();i+=4)
                    if(result.rgba[i]!=source.rgba[i] || result.rgba[i+1]!=source.rgba[i+1] || result.rgba[i+2]!=source.rgba[i+2])++changed;
            }
            if(argc==3 && std::string_view(argv[2])=="--capture" && std::string_view(scene)=="my0006"){
                GuestMemory::Transaction tx(m);media.begin_frame();
                try{tick_deferred_scene(m,media);tx.commit();media.end_frame(true);}
                catch(...){media.end_frame(false);throw;}
                const auto actual=images.current_frame();
                if(!actual || images.current_generation()!=media.selected_scene_generation() || !m.read_u32(0x236268))
                    throw std::runtime_error("Original MOVIE_LOOP_PLAY has not committed a video frame");
                auto presented=*actual;platform::draw_sab_layer(presented,m,visible_sab(m));
                capture_scene(presented,root/"captures/native-runtime/sn4-my0006-sab-native-window.png");
            }
            std::cout<<scene<<' '<<cue<<' '<<group.plan.primary_virtual_name<<' '<<group.animations.size()
                     <<' '<<visible.bytes.size()<<' '<<visible.frame<<' '<<changed<<'\n';
            if(std::string_view(scene)=="myb0036"){
                for(const char* label:{"myb0036_10","myb0036_20"}){
                    write_name(scratch+96,label);
                    const auto stream=invoke_cue_command(m,0x101ca8,registry,m.read_u32(scratch+64),scratch+96,nullptr);
                    if(!stream)throw std::runtime_error("Original production scene cue missing");
                    // 138E10 enqueues the actual group program, including SE_STOP_ALL and BGM_CHANGE_VOL.
                    invoke_cue_command(m,0x138e10,std::uint32_t(stream),scratch+96,0,nullptr);
                    if(m.read_u32(0x238724))throw std::runtime_error("Original production cue did not finish");
                }
            }
        }
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}
}
