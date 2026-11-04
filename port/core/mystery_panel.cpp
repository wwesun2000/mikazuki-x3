#include "mystery_panel.hpp"
#include "guest_memory.hpp"
#include "media_command.hpp"
#include "control_transfer.hpp"
#include "recovered.hpp"
#include <bit>

namespace kx3::mystery {
namespace {
constexpr u32 max_main=0x120000, texture=meta+0x210;
std::string name(const GuestMemory& m,u32 address){
    std::string s;
    for(unsigned i=0;i<48;++i){auto ch=m.read_u8(address+i);if(!ch)return s;s+=char(ch);}
    throw std::runtime_error("Unterminated panel filename");
}
// Five renameable file records in the original loader. Slot zero holds
// the active panel, the other four are the 14A0C8 portrait reservations.
constexpr u32 record(u32 n){return meta+n*48;}
u32 payload(u32 n){return n?slots+(n-1)*slot_capacity:main_file;}
u32 lookup(const GuestMemory& m,const std::string& path){
    for(u32 n=0;n<5;++n)if(m.read_u32(record(n)) && name(m,record(n)+4)==path)return n;
    return UINT32_MAX;
}
void install(GuestMemory& m,ExecutionServices* services,u32 n,const std::string& path,bool dummy){
    if(path.empty() || path.size()>=44)throw std::runtime_error("Invalid panel member name");
    if(!dummy){
        if(!services || !services->media)throw std::runtime_error("Missing ISO member for "+path);
        auto file=services->media->read_panel_member(path);
        if(file.empty() || file.size()>(n?slot_capacity:max_main))throw std::runtime_error("Panel member exceeds original file reservation");
        m.write_bytes(payload(n),file);
    }
    m.write_u32(record(n),1);
    for(u32 j=0;j<=path.size();++j)m.write_u8(record(n)+4+j,j==path.size()?0:std::uint8_t(path[j]));
}
}
bool active(const GuestMemory& m){
    const auto d=m.read_u32(descriptor);
    return d==culprit || d==memory;
}
u32 file_service(GuestMemory& m,ExecutionServices* s,u32 entry,u32 address,u32 argument,u32 size,u32 flags){
    const std::string path=name(m,address);
    if(entry==0x1453a8){
        if(argument==slot_capacity && size==0 && path.size()==10 && path.starts_with("xxpnh") &&
           path.ends_with(".dum") && path[5]>='0' && path[5]<='3'){
            install(m,s,1+u32(path[5]-'0'),path,true);return 0;
        }
        if(argument!=UINT32_MAX || size || !path.starts_with("PANEL/"))throw std::runtime_error("Unexpected original panel allocation "+path);
        install(m,s,0,path,false);return 0;
    }
    const auto n=lookup(m,path);
    if(entry==0x145980)return n==UINT32_MAX?0u:2u;
    if(n==UINT32_MAX)throw std::runtime_error("Missing resident panel file "+path);
    if(entry==0x1456f8)return payload(n);
    if(entry==0x145590 && n && size==UINT32_MAX && !flags){install(m,s,n,name(m,argument),false);return 0;}
    throw std::runtime_error("Unsupported original panel file call");
}
void bind_texture(GuestMemory& m,u32 address,u32 format,u32 width,u32 height){
    if(format || !width || !height || width>1024 || height>1024 || address<main_file ||
       address+std::uint64_t(width)*height*4>slots+4*slot_capacity)
        throw std::runtime_error("Unsupported panel texture transfer at 1363C8");
    m.write_u32(texture,address);m.write_u32(texture+4,width);m.write_u32(texture+8,height);
}
void remember_sprite(GuestMemory& m,u32 p,u32 option){
    const auto n=m.read_u32(sprite_count);
    if(n>=256 || p<packet || p+256>main_file || !m.read_u32(texture))throw std::runtime_error("Invalid panel sprite packet at 135CF8");
    const auto row=sprites+sprite_size*n;
    m.write_u32(row,m.read_u32(texture));
    m.write_u32(row+4,m.read_u32(texture+4));m.write_u32(row+8,m.read_u32(texture+8));
    for(auto [offset,reg]:{std::pair{12u,0xc0u},{16u,0xf0u},{20u,0xb0u},{24u,0xe0u},{28u,0xa0u}})
        m.write_u32(row+offset,m.read_u32(p+reg));
    m.write_u32(row+32,option);
    m.write_u32(sprite_count,n+1);
}
int selected(const GuestMemory& m){
    if(!active(m))return -1;
    if(m.read_u32(descriptor)==culprit){
        if(m.read_u32(0x2365e8) || m.read_u32(0x2365f8)!=128)return -1;
        return int(4*m.read_u32(0x236630)+m.read_u32(0x23662c));
    }
    if(m.read_u32(0x236728) || m.read_u32(0x236734)!=128)return -1;
    return int(m.read_u32(0x236780)*m.read_u32(0x236770)+m.read_u32(0x23676c));
}
int option_at(const GuestMemory& m,int x,int y){
    if(selected(m)<0)return -1;
    const bool who=m.read_u32(descriptor)==culprit;
    const auto n=m.read_u32(sprite_count);
    if(n>256)throw std::runtime_error("Invalid panel sprite count");
    for(unsigned i=n;i>0;--i){
        const u32 p=sprites+(i-1)*sprite_size,cell=m.read_u32(p+32);
        if(cell==UINT32_MAX || (who && (cell>=14 || m.read_u32(0x23e668+4*cell)==2)))continue;
        // The memory manager already excluded every cell whose source ID is 99.
        auto xx=[&](u32 a){return (int(m.read_u16(a))-0x6c00)/16;};
        auto yy=[&](u32 a){return (int(m.read_u16(a+2))-0x7900)/8;};
        if(x>=xx(p+12) && y>=yy(p+12) && x<xx(p+16) && y<yy(p+16))return int(cell);
    }
    return -1;
}
unsigned question_number(const GuestMemory& m){
    if(m.read_u32(descriptor)!=memory || !m.read_u32(sprite_count))return 0;
    const auto path=name(m,record(0)+4);
    if(path.size()!=18 || !path.starts_with("PANEL/memory0") || !path.ends_with(".dat") ||
       path[13]<'1' || path[13]>'6' || path!=name(m,m.read_u32(0x236790)))return 0;
    return unsigned(path[13]-'0');
}
void advance(GuestMemory& m,ExecutionServices* services){
    if(m.read_u32(0x236484))run_vm_context(m,0x147958,packet,0,0,0,services); // 135504
    if(!active(m))return;
    // 135AB0 / 135AB8 read the same physical held/edge fields used by the
    // original character panel. An input sample is consumed once per update.
    if(!invoke_recovered(m,0x15fec8,0x238700,0x238702,0,0,services)){
        m.write_u16(0x238700,0);m.write_u16(0x238702,0);
    }
    m.write_u32(sprite_count,0);m.write_u32(texture,0);
    const auto next=run_vm_context(m,0x149f58,packet,0,0,0,services); // 135550
    if(next<packet || next>main_file)throw std::runtime_error("Original panel draw exceeded its packet area");
    m.write_u32(meta+0x220,m.read_u32(0x235fa8)!=0);
}
void complete_requests(GuestMemory& m,ExecutionServices* services){
    // 135220 dispatches requests during the update following the draw.
    if(!m.read_u32(meta+0x220))return;
    run_vm_context(m,0x135080,0,0,0,0,services);
    m.write_u32(meta+0x220,0);
}
}
