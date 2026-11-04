#pragma once
#include "raster_loader.hpp"
#include "../chapter_card_messages.hpp"
#include "../../core/guest_memory.hpp"
#include <map>

namespace kx3::platform::windows {
class ChapterCardArt {
    std::map<unsigned,std::vector<std::uint8_t>> atlases_;
public:
    RasterFrame message(const std::filesystem::path& root,const GuestMemory& m,unsigned id){
        RasterFrame frame{640,448,std::vector<std::uint8_t>(640*448*4)};
        if(id>=40)return frame;
        for(unsigned i=chapter_card::starts[id];i<chapter_card::starts[id+1];++i){
            const auto command=chapter_card::draws[i];
            // 19E308's decorative background is supplied by the native menu.
            if(!command.textured)continue;
            const auto p=command.descriptor;
            const unsigned texture=m.read_u32(p);
            const auto table=0x22fc48+16*texture;
            const auto width=m.read_u32(table+8),height=m.read_u32(table+12);
            const bool indexed8=m.read_u32(table+4)>>16==19;
            if(!atlases_.contains(texture)){
                const char* hash=nullptr;
                switch(texture){
                case 0:hash="a8d403d60fabcfc253826e5dd2f509816209482a143e54867de51923b83eb9f9";break;
                case 2:hash="7e28666b0508d8df72a952686dbaf14599d09d2261144f6c5229de46a33007dd";break;
                case 4:hash="d7ff71421b2bec681366ca9545a70bf06d538a587734f593683fe02a283f785c";break;
                case 9:hash="6e05bbd74d8fbb9564da985d1dbcb0cbdc738a0c2a8d5a8c2bc43337d85a8608";break;
                case 10:hash="427db18536022f7daf19f320ae53a7a99045007a4045b4459a73bafb7688ce60";break;
                default:throw std::runtime_error("Unknown chapter texture in 1A3280");
                }
                const auto name=m.bytes(m.read_u32(table),64);
                const auto end=std::find(name.begin(),name.end(),0);
                if(end==name.end())throw std::runtime_error("Invalid chapter texture name");
                const auto size=indexed8?width*height+1024:width*height/2+64;
                atlases_.emplace(texture,read_disc_resource(root,std::string(name.begin(),end),hash,size));
            }
            auto& atlas=atlases_.at(texture);
            const int x=int(m.read_u32(p+4)),y=int(m.read_u32(p+8));
            const unsigned w=m.read_u32(p+12),h=m.read_u32(p+16);
            const unsigned u=m.read_u32(p+20),v=m.read_u32(p+24),uw=m.read_u32(p+28),vh=m.read_u32(p+32);
            const auto rgba=m.read_u32(p+36);
            if(w>640 || h>448 || !uw || !vh || uw>width || vh>height || u>width-uw || v>height-vh)
                throw std::runtime_error("Invalid chapter sprite geometry");
            for(unsigned j=0;j<h;++j)for(unsigned k=0;k<w;++k){
                const int px=x+int(k),py=y+int(j);
                if(px<0 || py<0 || px>=640 || py>=448)continue;
                const auto at=(v+j*vh/h)*width+u+k*uw/w;
                unsigned index=indexed8?atlas[at]:(atlas[at/2]>>(4*(at%2)))&15;
                if(indexed8)index=(index&~24u)|((index&8)<<1)|((index&16)>>1);
                const auto pal=width*height/(indexed8?1:2)+4*index;
                auto* dst=&frame.rgba[(py*640+px)*4];
                const auto alpha=std::min(255u,atlas[pal+3]*(rgba>>24)*255u/(128*128));
                if(!alpha)continue;
                for(unsigned c=0;c<3;++c)dst[c]=std::uint8_t(std::min(255u,atlas[pal+c]*((rgba>>(c*8))&255)/128));
                dst[3]=std::uint8_t(alpha);
            }
        }
        return frame;
    }
};
}
