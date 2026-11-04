#include "../core/runtime.hpp"
#include "../core/media_active.hpp"
#include "../platform/windows/project_media.hpp"
#include "../platform/windows/project_font.hpp"
#include "../platform/windows/raster_loader.hpp"
#include "../platform/text_layer.hpp"
#include "../tests/story_frame_scenarios.hpp"
#include "../core/font_resource.hpp"
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>

namespace {
std::string quote(const std::string& s){std::ostringstream out;out<<std::quoted(s);return out.str();}
std::string hex(std::uint32_t v){std::ostringstream out;out<<"0x"<<std::hex<<std::setw(8)<<std::setfill('0')<<v;return out.str();}
void write_layer(const kx3::GuestMemory& memory, std::uint32_t manager,
                 const std::filesystem::path& root, const std::filesystem::path& output) {
    const auto assets = root / "local/assets/EFFECT";
    const auto mark = kx3::platform::windows::read_verified_source(assets/"mark.ctf","1640696c4886e47890bd25651c6f1075ca9cf4c2a05a689e2fc373974ae296fb",8384);
    const auto love = kx3::platform::windows::read_verified_source(assets/"love.ctf","b0b84740ca2a246b2c50d94851c850a4b568a068a0e7faadaf16063716e0c952",8384);
    const kx3::platform::TextAtlasResource atlases[]{{0,mark},{4,love}};
    const auto font=memory.read_u32(manager+0x3c);
    const auto frame=kx3::platform::render_text_layer(memory,font,atlases);
    std::ofstream file(output,std::ios::binary);
    file.exceptions(std::ios::failbit|std::ios::badbit);
    file.write(reinterpret_cast<const char*>(frame.rgba.data()),std::streamsize(frame.rgba.size()));
    file.close();
    std::size_t visible=0;
    for(std::size_t i=3;i<frame.rgba.size();i+=4) if(frame.rgba[i])++visible;
    const auto count=[&](unsigned offset){return memory.read_u32(memory.read_u32(memory.read_u32(font+offset))+4);};
    std::cout<<"{\"layer\":\"original_text\",\"width\":"<<frame.width<<",\"height\":"<<frame.height
             <<",\"primary_nodes\":"<<count(8)<<",\"ruby_nodes\":"<<count(12)<<",\"visible_pixels\":"<<visible<<"}\n";
}
}
int wmain(int argc,wchar_t** argv) {
    try {
        if(argc!=2 && argc!=4 && argc!=5)throw std::runtime_error("Supply project root and a supported probe mode");
        if(argc==5 && std::wstring_view(argv[2])==L"--font-image"){
            const std::string program=std::filesystem::path(argv[3]).string();
            kx3::GuestMemory new_game;constexpr std::uint32_t base=0x400000;
            const auto font=kx3::platform::windows::load_project_font(new_game,base,argv[1],program);
            const auto length=std::filesystem::file_size(std::filesystem::path(argv[1])/"local/assets/SCENARIO"/(program+".fnt"));
            if(length>kx3::GuestMemory::size-base)throw std::runtime_error("Invalid verified font length");
            const auto image=new_game.bytes(base,std::size_t(length));
            std::ofstream file(std::filesystem::path(argv[4]),std::ios::binary);
            file.exceptions(std::ios::failbit|std::ios::badbit);
            file.write(reinterpret_cast<const char*>(image.data()),std::streamsize(image.size()));file.close();
            std::cout<<"{\"groups\":"<<font.groups<<",\"glyphs\":"<<font.glyphs<<",\"descriptor\":"<<font.descriptor<<"}\n";
            return 0;
        }
        _setmode(_fileno(stdin),_O_BINARY);
        std::vector<std::uint8_t> ram(kx3::GuestMemory::size);
        std::cin.read(reinterpret_cast<char*>(ram.data()),ram.size());
        if(!std::cin || std::cin.peek()!=EOF)throw std::runtime_error("Expected complete original RAM fixture");
        kx3::GuestMemory m;m.write_bytes(0,ram);
        const auto manager=m.read_u32(0x235e40),script=m.read_u32(manager+0x38);
        if(argc==4 && std::wstring_view(argv[2])==L"--font-resource"){
            const auto base=m.read_u32(0x236f30);
            const auto file=kx3::platform::windows::read_verified_source(std::filesystem::path(argv[1])/"local/assets/SCENARIO/sn4g.fnt",
                "c12f602b3716b1dce68d6bdbcb58b45dbe29d67dab0a5ef7dbb35210e3d370b3",1098219);
            kx3::GuestMemory new_game;
            if(std::wstring_view(argv[3])!=L"sn4g")throw std::runtime_error("This original-state comparison uses the sn4g font");
            const auto font=kx3::platform::windows::load_project_font(new_game,base,argv[1],"sn4g");
            const auto elf=kx3::platform::windows::read_verified_source(std::filesystem::path(argv[1])/"local/extracted/SLPM_664.52",
                "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160",1290132);
            new_game.write_bytes(0x236f38,std::span(elf).subspan(0x236f38-0xff000,4));
            kx3::initialize_native_font_palette(new_game);
            const auto palette=new_game.bytes(0x1e44180,64);
            if(!std::equal(palette.begin(),palette.end(),m.bytes(0x1e44180,64).begin()))
                throw std::runtime_error("Native cold font palette differs from original running state");
            const auto actual=new_game.bytes(base,file.size()),expected=m.bytes(base,file.size());
            if(font.glyphs!=3430 || new_game.read_u32(0x236f30)!=base || !std::equal(actual.begin(),actual.end(),expected.begin()))
                throw std::runtime_error("Newly initialized native font differs from original resident resource");
            auto bad=file;std::fill_n(bad.begin()+28+16,4,0xff);
            bool rejected=false;
            try{(void)kx3::install_font_resource(new_game,base,bad);}catch(const std::invalid_argument&){rejected=true;}
            if(!rejected || !std::equal(actual.begin(),actual.end(),expected.begin()))throw std::runtime_error("Malformed font changed live state");
            std::cout<<"{\"check\":\"install_original_font\",\"glyphs\":"<<font.glyphs<<",\"resident_bytes_equal\":"<<file.size()
                     <<",\"corruption_rejected\":true,\"palette_bytes_equal\":64}\n";
            return 0;
        }
        if(argc==5 && std::wstring_view(argv[2])==L"--frames"){
            const std::wstring_view scenario(argv[3]);
            if(scenario!=L"choice" && scenario!=L"timed")throw std::runtime_error("Unknown manager frame scenario");
            kx3::tests::run_story_frames(m,argv[1],scenario==L"choice",argv[4]);return 0;
        }
        if(argc==5)throw std::runtime_error("Unknown manager-frame probe arguments");
        if(argc==4 && std::wstring_view(argv[2])==L"--snapshot-layer"){
            write_layer(m,manager,argv[1],argv[3]);return 0;
        }
        if(argc==4 && std::wstring_view(argv[2])!=L"--yield-layer")throw std::runtime_error("Unknown text layer mode");
        {
            kx3::platform::windows::ProjectImageServices missing(std::filesystem::path(argv[1])/"absent-native-media-test-source");
            kx3::SourceMediaActiveBackend backend(missing);
            kx3::ExecutionServices services{nullptr,&backend};
            bool rejected=false;
            try{(void)kx3::step_script_atomic(m,manager,&services);}catch(const std::exception&){rejected=true;}
            if(!rejected || !missing.prepared().empty() || !std::equal(ram.begin(),ram.end(),m.bytes(0,ram.size()).begin()))
                throw std::runtime_error("Missing actual asset did not preserve original RAM/prepared state");
            std::cout<<"{\"check\":\"missing_asset_preserves_state\",\"passed\":true}\n";
        }
        kx3::platform::windows::ProjectImageServices images(argv[1]);
        kx3::SourceMediaActiveBackend backend(images);
        kx3::ExecutionServices services{nullptr,&backend};
        for(unsigned step=0;step<512;++step) {
            const auto cursor=m.read_u32(script+0xd8);
            const auto opcode=m.read_u8(cursor);
            const bool text=m.read_u32(manager+0x2b4)!=0;
            std::copy(m.bytes(0,ram.size()).begin(),m.bytes(0,ram.size()).end(),ram.begin());
            const auto prepared_before=images.prepared().size();
            try {
                const auto result=kx3::step_script_atomic(m,manager,&services);
                std::cout<<"{\"step\":"<<step<<(text?",\"text_byte\":":",\"opcode\":")<<unsigned(opcode)
                         <<",\"cursor\":"<<quote(hex(cursor))<<",\"cursor_after\":"<<quote(hex(m.read_u32(script+0xd8)))
                         <<",\"return_value\":"<<result<<",\"prepared_generations\":"<<images.prepared().size()
                         <<",\"current_generation\":"<<images.current_generation()<<"}\n";
                if(step==0) {
                    if(opcode!=0x72 || images.prepared().empty() || images.current_generation()!=0)
                        throw std::runtime_error("First real context step did not prepare resources without activating presentation");
                    for(const auto& [generation,state]:images.prepared())for(const auto& [name,frame]:state.frames)
                        std::cout<<"{\"prepared_asset\":"<<quote(name)<<",\"generation\":"<<generation
                                 <<",\"width\":"<<frame->width<<",\"height\":"<<frame->height
                                 <<",\"actual_rgba_bytes\":"<<frame->rgba.size()<<"}\n";
                }
                if(result){
                    if(argc==4)write_layer(m,manager,argv[1],argv[3]);
                    return 0;
                }
            } catch(const std::exception& error) {
                const bool unchanged=std::equal(ram.begin(),ram.end(),m.bytes(0,ram.size()).begin());
                std::cout<<"{\"step\":"<<step<<(text?",\"text_byte\":":",\"opcode\":")<<unsigned(opcode)<<",\"status\":\"blocked\",\"error\":"<<quote(error.what())
                         <<",\"full_ram_rolled_back\":"<<(unchanged?"true":"false")
                         <<",\"prepared_state_unchanged\":"<<(images.prepared().size()==prepared_before?"true":"false")<<"}\n";
                if(step==0 || !unchanged || images.prepared().size()!=prepared_before)return 2;
                return argc==4?3:0;
            }
        }
        throw std::runtime_error("Source step budget reached before yield");
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}
}
