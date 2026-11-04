#include "staff_roll.hpp"
#include "guest_memory.hpp"
#include "control_transfer.hpp"
#include <algorithm>
#include <bit>
#include <stdexcept>

namespace kx3::credits {
namespace {
constexpr u32 parts=16, stride=4+parts*24, metadata=0x19b0100;
int signed_word(u32 w){return std::bit_cast<std::int32_t>(w);}
}
void install(GuestMemory& m,std::span<const std::uint8_t> file,u32 program){
    if(file.empty() || file.size()>=copy-source || program>2)throw std::invalid_argument("Invalid original staff roll");
    m.write_bytes(source,file);m.write_u32(file_size,u32(file.size()));m.write_u32(edition,program);
}
void remember_line(GuestMemory& m,u32 slot,u32 offset,u32 cursor,bool continued,bool align){
    if(slot>=14 || offset>=m.read_u32(file_size))throw std::runtime_error("Unbound original credit line");
    const auto surface=m.read_u32(first_row+20*slot+4);
    if(cursor<surface || cursor>=surface+0x3480)throw std::runtime_error("Credit cursor outside its row");
    const auto row=metadata+slot*stride, count=continued?m.read_u32(row):0;
    if(count>=parts)throw std::runtime_error("Too many continued credit fragments");
    const auto p=row+4+24*count;
    m.write_u32(p,offset);m.write_u32(p+4,(cursor-surface)*2);
    const auto size=m.read_u32(0x23680c);
    m.write_u32(p+8,size?size:m.read_u32(m.read_u32(0x236f30)+16));
    m.write_u32(p+12,align?m.read_u32(0x236830):UINT32_MAX);m.write_u32(p+16,m.read_u32(0x23682c));
    m.write_u32(p+20,std::max(0,signed_word(m.read_u32(0x236838))-int(m.read_u32(p+8)/2)));
    m.write_u32(row,count+1);
}
std::vector<Line> visible_lines(const GuestMemory& m){
    std::vector<Line> lines;
    if(!m.read_u32(0x236824) || !m.read_u32(0x2367f8))return lines;
    const auto scroll=signed_word(m.read_u32(0x236818))>>4;
    for(u32 slot=0;slot<14;++slot){
        const auto r=first_row+20*slot;
        if(!m.read_u32(r))continue;
        const auto y=signed_word(m.read_u32(r+8))-scroll+448;
        if(y>=448 || y+int(m.read_u32(r+16))<=0)continue;
        const auto row=metadata+slot*stride,count=m.read_u32(row),file_length=m.read_u32(file_size);
        if(count>parts)throw std::runtime_error("Invalid credit fragment count");
        for(u32 i=0;i<count;++i){
            const auto p=row+4+24*i,offset=m.read_u32(p);
            if(offset>=file_length)throw std::runtime_error("Credit fragment outside original member");
            const auto raw=m.bytes(source+offset,file_length-offset);
            const auto end=std::find_if(raw.begin(),raw.end(),[](auto c){return !c || c=='\n' || c=='\r';});
            std::string text(raw.begin(),end);
            if(text.ends_with("\x81\x8f"))text.resize(text.size()-2);
            lines.push_back({offset,std::move(text),signed_word(m.read_u32(p+4)),y+int(m.read_u32(p+20)),
                             int(m.read_u32(p+8)),int(m.read_u32(p+12)),signed_word(m.read_u32(p+16))});
        }
    }
    return lines;
}
void advance(GuestMemory& m,ExecutionServices* services){
    if(!m.read_u32(0x236824))return;
    run_scenario_return(m,0x14d6e8,0,0,services); // 100A88
    if(m.read_u32(0x2367f8)){
        const auto end=run_scenario_return(m,0x14df38,packet,0,services);
        if(end<packet || end>stack-0x4000)throw std::runtime_error("Invalid original staff GS packet extent");
    }
}
}
