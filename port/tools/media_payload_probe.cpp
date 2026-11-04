#include "../core/media_active.hpp"
#include "../core/guest_memory.hpp"
#include "../core/pss_audio.hpp"
#include "../platform/sab_layer.hpp"
#include <iostream>
#include <fstream>
#include <iterator>
#include <string_view>
#include <fcntl.h>
#include <io.h>

int main(int argc,char** argv) {
    try {
        if(argc==2 && std::string_view(argv[1])=="--blend"){
            _setmode(_fileno(stdout),_O_BINARY);
            for(int difference=-255;difference<=255;++difference){
                const int base=difference<0?255:0,source=base+difference;
                for(int f=0;f<=128;++f)std::cout.put(char(kx3::platform::source_over_channel(source,base,f)));
                for(int f=0;f<=255;++f)std::cout.put(char(kx3::platform::fog_channel(source,base,f)));
            }
            return !std::cout;
        }
        if(argc==2 && std::string_view(argv[1])=="--capture") {
            kx3::GuestMemory m;
            m.write_u32(0x236114,0x240000);m.write_u32(0x236118,0x2cc000);
            unsigned mode,left,attempts,field,active,pass;
            while(std::cin>>mode>>left>>attempts>>field>>active>>pass) {
                m.write_u32(0x236108,mode);m.write_u32(0x236104,left);m.write_u32(0x23610c,attempts);
                m.write_u32(0x2062bc,active);m.write_u32(0x236188,6);
                std::vector<unsigned> copies;
                kx3::capture_source_display_field(m,pass,field,[&](auto destination,auto source_field){
                    copies.push_back((destination==0x240000?0:2)+source_field);
                });
                std::cout<<m.read_u32(0x236104)<<' '<<m.read_u32(0x23610c);
                for(auto n:copies)std::cout<<' '<<n;
                std::cout<<'\n';
            }
            return 0;
        }
        const auto mode=argc==3?std::string_view(argv[1]):std::string_view{};
        if(mode!="--pss" && mode!="--sab")return 2;
        std::ifstream src(argv[2],std::ios::binary);
        if(!src)throw std::runtime_error("Missing PSS");
        src.seekg(0,std::ios::end);const auto size=src.tellg();src.seekg(0);
        if(size<=0 || size>0x40000000)throw std::runtime_error("Unexpected PSS size");
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
        if(!src.read(reinterpret_cast<char*>(bytes.data()),size))throw std::runtime_error("Short PSS read");
        if(mode=="--sab"){
            // Use the three source default GS globals captured in the draw oracle.
            kx3::GuestMemory m;m.write_u32(0x236460,0x3f400000);m.write_u32(0x236480,0x43000000);
            m.write_u32(0x236468,UINT32_MAX);m.write_u32(0x23646c,1);m.write_u32(0x206810,1);
            m.write_u32(0x206258,0x3f000000);
            const kx3::SabBlob blob{"sample.sab",bytes};
            kx3::install_sab_files(m,std::span(&blob,1));
            const auto info=kx3::inspect_sab_file(bytes);const auto file=m.read_u32(0x1830028);
            kx3::invoke_sab_animation(m,0x1397b0,file);
            for(unsigned i=0;i<info.frames*2+1;++i){
                kx3::advance_sab_draw(m);
                const auto visible=kx3::visible_sab(m);
                if(visible.bytes.size()!=bytes.size())throw std::runtime_error("SAB was not presented");
                if(i<info.frames*2 && visible.frame!=i/2)throw std::runtime_error("Original half-frame cadence differs");
                if(i%2 || i/2>=info.frames)continue;
                kx3::platform::RasterFrame image{640,448,{}};image.rgba.resize(640*448*4,128);
                kx3::platform::draw_sab_layer(image,m,visible);
                std::uint64_t fingerprint=14695981039346656037ull;
                for(auto v:image.rgba)fingerprint=(fingerprint^v)*1099511628211ull;
                std::cout<<i/2<<' '<<fingerprint<<'\n';
            }
            if(kx3::invoke_sab_animation(m,0x146be0,0x2062e0))throw std::runtime_error("Original wait did not end");
            return 0;
        }
        const auto audio=kx3::decode_pss_audio(bytes);
        if(!audio)return 0;
        _setmode(_fileno(stdout),_O_BINARY);
        std::cout<<audio->rate<<' '<<audio->channels<<' '<<audio->first_audio_pts90k<<' '
                 <<audio->first_video_pts90k<<' '<<audio->audio_offset90k<<'\n';
        std::cout.write(reinterpret_cast<const char*>(audio->interleaved.data()),std::streamsize(audio->interleaved.size()*2));
        return !std::cout;
    } catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}
}
