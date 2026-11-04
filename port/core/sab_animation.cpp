#include "sab_animation.hpp"
#include <algorithm>
#include <bit>
#include <cmath>

namespace kx3 {
namespace {
using u32=std::uint32_t;using Bytes=std::span<const std::uint8_t>;
constexpr u32 cache=0x1830000,ceiling=0x19b0000,player=0x2062e0;
void need(bool cond,const char* msg){if(!cond)throw std::runtime_error(msg);}
u32 word(Bytes b,std::size_t p){
    need(p<=b.size() && b.size()-p>=4,"146960 truncated SAB word");
    return u32(b[p])|(u32(b[p+1])<<8)|(u32(b[p+2])<<16)|(u32(b[p+3])<<24);
}
void range(Bytes b,u32 p,std::uint64_t bytes){need(p<=b.size() && bytes<=b.size()-p,"146F78 SAB texture exceeds original file");}
float f(const GuestMemory& m,u32 p){return std::bit_cast<float>(m.read_u32(p));}
void bind(GuestMemory& m,u32 obj,u32 file) { // 146960, including the source's two header representations.
    m.write_u32(obj,file);m.write_u32(obj+0x4c,1);
    const auto offset=m.read_u32(file);
    const auto header=file+offset,base=offset?file:m.read_u32(file+8);
    m.write_u32(obj+0x68,header);m.write_u32(obj+0x6c,base);
    m.write_u32(obj+0x74,header+28);m.write_u32(obj+0x80,m.read_u16(header+4));
    m.write_u32(obj+0x50,m.read_u16(header+6));m.write_u32(obj+0x78,m.read_u32(header+12));
    m.write_u32(obj+0x84,base+m.read_u32(header+16));m.write_u32(obj+0x88,base+m.read_u32(header+20));
    m.write_u32(obj+0x8c,m.read_u32(header+24));
}
void consume(GuestMemory& m,u32 obj) { // 1469E0
    for(unsigned tries=0;tries<8;++tries) {
        const auto head=m.read_u32(obj+0x44),tail=m.read_u32(obj+0x48);
        need(head<8 && tail<8,"Invalid original SA_PLAY queue");if(head==tail)return;
        const auto flag=m.read_u32(obj+0x24+4*head);
        if(m.read_u32(obj) && (flag&1) && !m.read_u32(obj+0x54))return;
        bind(m,obj,m.read_u32(obj+4+4*head));
        m.write_u32(obj+0x64,flag&2?std::bit_cast<u32>(float(m.read_u32(obj+0x78))):0);
        m.write_u32(obj+0x54,0);m.write_u32(obj+0x44,(head+1)%8);
    }
}
}
SabFileInfo inspect_sab_file(Bytes bytes) {
    const auto h=word(bytes,0);range(bytes,h,28);
    const auto format=word(bytes,h+4);
    need(h && word(bytes,h)==1 && (format&65535)==2 && (format>>16)<=1 && word(bytes,h+8)==0,
         "146960 unsupported SAB disk header");
    SabFileInfo s{h,word(bytes,h+12),word(bytes,h+16),word(bytes,h+20),word(bytes,h+24)+1};
    need(s.frames && s.frames<=36000 && s.colorshift<8,"Invalid SAB frame count or downsample");
    range(bytes,h+28,4ull*s.frames);range(bytes,s.color_palette,1024);
    return s;
}
SabLayer inspect_sab_layer(Bytes b,const SabFileInfo& s,u32 frame) {
    need(frame<s.frames,"146F78 invalid SAB frame");
    const auto p=word(b,s.header+28+4*frame);range(b,p,56);
    need(word(b,p)==1 && word(b,p+12)==1 && !word(b,p+16),"146F78 unsupported SAB layer mode");
    const auto w=word(b,p+32),h=word(b,p+36),sx=word(b,p+48),sy=word(b,p+52);
    need(w && h && w<=640 && h<=448 && word(b,p+40)==w && word(b,p+44)==h && sx<=1 && sy==0,
         "146F78 unsupported SAB geometry");
    const auto palette_index=word(b,p+20)/2+4;
    need(palette_index<=5,"146F78 unknown SAB mask palette");
    SabLayer l{word(b,p+4),word(b,p+8),s.mask_palettes+palette_index*64,
               word(b,p+24),word(b,p+28),w,h,w>>s.colorshift,h>>s.colorshift,w>>sx,h>>sy};
    need(l.x<=640 && l.y<=448 && l.color_width && l.color_height,"Invalid SAB coordinates");
    range(b,l.colors,std::uint64_t(l.color_width)*l.color_height);range(b,l.mask,std::uint64_t(l.mask_width)*l.mask_height/2);
    range(b,l.mask_palette,64);return l;
}
void install_sab_files(GuestMemory& m,std::span<const SabBlob> files) {
    // Native file-service mappings of immutable FAD bytes. The active source
    // player stores real guest pointers. Preloads do not disturb this pool.
    need(files.size()<=4,"Too many original SAB resources in one scene");
    if(files.empty() && !m.read_u32(cache))return;
    u32 address=cache+256;
    m.write_u32(cache,u32(files.size()));m.write_u32(cache+4,0);m.write_u32(cache+8,0);
    for(u32 i=0;i<files.size();++i){
        const auto& v=files[i];const auto n=v.bytes.size();
        need(v.name.size()<24 && address<=ceiling && n<=ceiling-address,"SAB group exceeds reserved active-file pool");
        const auto info=inspect_sab_file(v.bytes);
        for(u32 j=0;j<info.frames;++j)(void)inspect_sab_layer(v.bytes,info,j);
        const auto row=cache+16+32*i;
        for(u32 j=0;j<24;++j)m.write_u8(row+j,j<v.name.size()?std::uint8_t(v.name[j]):0);
        m.write_u32(row+24,address);m.write_u32(row+28,u32(n));m.write_bytes(address,v.bytes);
        address=(address+u32(n)+63)&~63u;
    }
}
u32 find_sab_file(const GuestMemory& m,u32 filename) {
    const auto count=m.read_u32(cache);need(count<=4,"Corrupt SAB file mapping");
    for(u32 i=0;i<count;++i) {
        const auto row=cache+16+32*i;bool same=true;
        for(u32 j=0;j<24;++j){
            const auto ch=m.read_u8(filename+j);if(ch!=m.read_u8(row+j)){same=false;break;}if(!ch)break;
        }
        if(same)return m.read_u32(row+24);
    }
    throw std::runtime_error("1456F8 SA_PLAY file is not resident");
}
std::uint64_t invoke_sab_animation(GuestMemory& m,u32 e,u32 obj,u32 a1,u32 a2) {
    switch(e) {
    case 0x146960:bind(m,obj,a1);return 0;
    case 0x1469e0:consume(m,obj);return 0;
    case 0x1397b0:return invoke_sab_animation(m,0x146b50,player,obj,1);
    case 0x146b50:{
        const auto tail=m.read_u32(obj+0x48);need(tail<8,"Invalid SAB queue tail");
        const auto next=(tail+1)%8;
        if(next!=m.read_u32(obj+0x44)){
            m.write_u32(obj+0x24+4*tail,a2);m.write_u32(obj+0x48,next);
            m.write_u32(obj+4+4*tail,a1);consume(m,obj);
        }
        return 0;
    }
    case 0x146be0:
        return m.read_u32(obj) && m.read_u32(obj+0x4c) && !(float(std::bit_cast<std::int32_t>(m.read_u32(obj+0x78)))<=f(m,obj+0x64));
    case 0x146c18:
        if(m.read_u32(obj)){
            while(m.read_u32(obj+0x44)!=m.read_u32(obj+0x48)){
                const auto head=m.read_u32(obj+0x44);need(head<8 && m.read_u32(obj+0x48)<8,"Invalid SAB forward queue");
                bind(m,obj,m.read_u32(obj+4+4*head));m.write_u32(obj+0x44,(head+1)%8);
            }
            m.write_u32(obj+0x54,0);m.write_u32(obj+0x64,std::bit_cast<u32>(float(m.read_u32(obj+0x78))));
        }
        return 0;
    default:throw std::invalid_argument("Unrecovered SAB function");
    }
}
void advance_sab_draw(GuestMemory& m){
    if(!m.read_u32(cache))return;
    // 1352F4 -> 137308 and 1353B8..C4 gate the normal scene draw pass.
    if(!m.read_u32(0x206810) || m.read_u32(0x235fbc))return;
    const auto speed=f(m,0x236458)!=0?m.read_u32(0x236458):m.read_u32(0x206258);
    m.write_u32(player+0x60,speed);consume(m,player);
    m.write_u32(cache+4,0);
    const auto file=m.read_u32(player);
    if(file && m.read_u32(player+0x4c)){
        const auto phase=f(m,player+0x64);const auto length=m.read_u32(player+0x78);
        need(length && std::isfinite(phase) && phase>=0 && phase<2147483648.0f,"146F78 invalid SAB animation clock");
        const auto sample=u32(phase);
        if(sample>=length)m.write_u32(player+0x54,1);
        const auto frame=m.read_u32(player+0x50)?sample%length:std::min(sample,length-1);
        m.write_u32(cache+4,file);m.write_u32(cache+8,frame);
        const auto row=m.read_u32(m.read_u32(player+0x74)+frame*4)+m.read_u32(player+0x6c);
        if(m.read_u32(row))m.write_u32(player+0x7c,m.read_u32(row+12));
    }
    if(!m.read_u32(0x236104) && !m.read_u32(0x2062ac))m.write_u32(player+0x64,std::bit_cast<u32>(f(m,player+0x64)+f(m,player+0x60)));
}
SabDisplay visible_sab(const GuestMemory& m){
    const auto file=m.read_u32(cache+4),count=m.read_u32(cache);
    if(!file)return {};
    need(count<=4,"Invalid SAB resource count");
    for(u32 i=0;i<count;++i){
        const auto row=cache+16+32*i,size=m.read_u32(row+28);
        if(m.read_u32(row+24)==file){need(file>=cache+256 && file<=ceiling && size<=ceiling-file,"Invalid SAB display mapping");return {m.bytes(file,size),m.read_u32(cache+8)};}
    }
    throw std::runtime_error("SAB display references an expired resource");
}
}
