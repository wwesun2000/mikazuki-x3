#include "system_charts.hpp"
#include "control_transfer.hpp"
#include "source_libc.hpp"
#include <array>
#include <algorithm>
#include <bit>
#include <stdexcept>
#include <string_view>

namespace kx3 {
namespace {
using u32=std::uint32_t;
constexpr u32 endings=0x1e4bd08, ending_bits=0x1e4bf08, ending_count=0x2381a0;
constexpr unsigned max_entries=128;
void index_list(GuestMemory& m,u32 base,std::span<const std::uint8_t> data,u32 table) {
    if(data.size()<2)throw std::runtime_error("Truncated 1AB330 / 1AF010 record file");
    const unsigned n=data[0];
    if(n>max_entries)throw std::runtime_error("1AB330 original pointer capacity exceeded");
    std::array<u32,max_entries> records{};
    std::size_t offset=2;
    for(unsigned i=0;i<n;++i) {
        if(offset>=data.size())throw std::runtime_error("Truncated 1AB330 record");
        records[i]=base+u32(offset);
        if(data[offset]) {
            // 1AB388: type byte, thirteen label bytes, zero-terminated title,
            // then a second byte before the following record.
            offset+=14;
            while(offset<data.size() && data[offset])++offset;
        }
        if(offset+2>data.size())throw std::runtime_error("Missing 1AB330 record terminator");
        offset+=2;
    }
    for(unsigned i=0;i<max_entries;++i)m.write_u32(table+4*i,records[i]);
}
void install_progress_callbacks(GuestMemory& m,u32 table) { // 19C768.
    m.write_bytes(0x1e4ab68,m.bytes(table,56));
    m.write_u8(0x237f80,0);m.write_u8(0x237f8b,1);m.write_u8(0x237f81,1);
    m.write_u32(0x237f84,1);m.write_u8(0x237f89,1);m.write_u8(0x237f88,0);m.write_u8(0x237f8a,0);
    for(const auto p : {0x237f8c,0x237f90,0x237f94})m.write_u32(p,0);
    for(const auto p : {0x1e4abb0,0x1e4aba0,0x1e4abc0})m.write_u8(p,0);
}
}

std::uint32_t consume_source_ending_list(GuestMemory& m) {
    constexpr u32 slot=0x238aa8+5*8;
    const auto base=m.read_u32(slot),size=m.read_u32(slot+4);
    if(!base && size==0xffffffffu)throw std::runtime_error("100718 requires pending original file slot 5");
    if(!base)return 0;
    const auto data=m.bytes(base,size);
    index_list(m,base,data,endings);
    const auto n=data[0];
    m.write_u32(slot,0);m.write_u32(slot+4,0xffffffffu); // 1007D8 consumes the ready slot.
    m.write_u32(ending_count,n);m.write_u32(ending_count+4,base);
    m.write_u32(ending_count+8,0);m.write_u32(ending_count+12,0);m.write_u32(ending_count+16,1);
    m.write_bytes(ending_bits,std::array<std::uint8_t,16>{});
    return 1;
}

void install_ending_list(GuestMemory& m, u32 base, std::span<const std::uint8_t> data) {
    if(!base || data.size()>GuestMemory::size || base>GuestMemory::size-data.size())
        throw std::invalid_argument("Invalid 1AB330 file slot 5 allocation");
    if(m.read_u32(ending_count+4))
        throw std::runtime_error("1AB330 ending list is already live");
    GuestMemory::Transaction tx(m);
    m.write_bytes(base,data);
    m.write_u32(0x238ad0,base);m.write_u32(0x238ad4,u32(data.size()));
    consume_source_ending_list(m);
    tx.commit();
}

bool can_replay_ending(const GuestMemory& m,u32 index) {
    // 1ABB48 accepts only the third edition's row 78. 1AB5E8 also
    // enables that row when variable 17C equals one before it is recorded.
    return index==78 && m.read_u32(0x235b00)==1 && index<m.read_u32(ending_count) &&
           ((m.read_u8(ending_bits+(index>>3))&(1u<<(index&7))) || m.read_u16(0x238af0+0x17c*2)==1);
}
std::vector<EndingListEntry> ending_list_entries(const GuestMemory& m) {
    if(!m.read_u32(ending_count+4))return {};
    const auto n=m.read_u32(ending_count);
    if(n>max_entries)throw std::runtime_error("Corrupt 1AB330 ending count");
    std::vector<EndingListEntry> entries(n);
    for(u32 i=0;i<n;++i) {
        const auto p=m.read_u32(endings+4*i);
        const bool reached=(m.read_u8(ending_bits+(i>>3))&(1u<<(i&7)))!=0; // 1AB578.
        entries[i].reached=reached;
        entries[i].replay_prompt=!reached && can_replay_ending(m,i);
        if(reached && p && m.read_u8(p)) {
            for(u32 a=p+14; m.read_u8(a); ++a)entries[i].title_cp932.push_back(char(m.read_u8(a)));
        }
    }
    return entries;
}
std::uint32_t mark_source_ending(GuestMemory& m,u32 label) { // 1AB4A8.
    const auto n=m.read_u32(ending_count);
    if(!m.read_u32(ending_count+4))return 0;
    if(n>max_entries)throw std::runtime_error("Corrupt 1AB4A8 ending count");
    for(u32 i=0;i<n;++i) {
        const auto row=m.read_u32(endings+i*4);
        if(m.read_u8(row) && !source_strcmp(m,row+1,label)) {
            const auto flag=ending_bits+(i>>3);
            m.write_u8(flag,m.read_u8(flag)|(1u<<(i&7)));return 1;
        }
    }
    return 0;
}
void install_chapter_list(GuestMemory& m,ChapterFileStorage s,std::span<const std::uint8_t> data,
                         std::span<const std::uint8_t> texture) {
    if(!s.records || !s.textures || !s.work || data.empty() || texture.size()!=2*0x5480 ||
       m.read_u32(0x238208))throw std::invalid_argument("Invalid original 1AF010 / 1AF550 chapter inputs");
    const std::array<std::pair<u32,std::size_t>,3> regions{{{s.records,data.size()},{s.textures,texture.size()},{s.work,0x20c}}};
    for(std::size_t i=0;i<regions.size();++i) {
        const auto [p,n]=regions[i];(void)m.bytes(p,n);
        for(std::size_t j=0;j<i;++j) {
            const auto [q,l]=regions[j];
            if(p<q+l && q<p+n)throw std::invalid_argument("Overlapping 1AF550 chapter buffers");
        }
    }
    GuestMemory::Transaction tx(m);
    m.write_bytes(s.records,data);m.write_bytes(s.textures,texture);
    index_list(m,s.records,data,0x1e4bf80);
    m.write_u32(0x238200,0);m.write_u8(0x1e4bf70,0);
    m.write_bytes(0x1e4c180,std::array<std::uint8_t,16>{});
    m.write_u32(0x238204,data[0]);m.write_u32(0x238208,s.records);
    install_progress_callbacks(m,0x231bc0);
    for(unsigned i=7;i<=8;++i){m.write_u32(0x238aa8+i*8,0);m.write_u32(0x238aac+i*8,0xffffffffu);}
    m.write_u32(0x2389a8,s.textures);m.write_u32(0x2389ac,u32(texture.size()));
    m.write_u32(0x238210,1);m.write_u32(0x238214,0);m.write_u32(0x238218,s.work);m.write_u32(0x23821c,0xffffffffu);
    for(u32 i=0;i<2;++i) {
        const auto p=s.textures+i*0x5480,node=0x1e4c1a0+i*28;
        m.write_u32(0x1e4c190+8*i,p+0x5080);m.write_u32(0x1e4c194+8*i,4);
        m.write_u32(node,p);m.write_bytes(node+4,m.bytes(0x231c14,24));
    }
    tx.commit();
}
void prepare_chapter_menu(GuestMemory& m) { // 1AF6E0.
    const auto work=m.read_u32(0x238218),n=m.read_u32(0x238204);
    if(!work || !m.read_u32(0x238208) || n>max_entries)
        throw std::runtime_error("1AF6E0 needs initialized 1AF010 / 1AF550 chapter data");
    m.write_u32(0x23821c,0xffffffffu);
    m.write_u32(work+4,0);
    u32 total=0;
    for(u32 i=0;i<n;++i) {
        if(!(m.read_u8(0x1e4c180+(i>>3))&(1u<<(i&7))))continue;
        const auto row=m.read_u32(0x1e4bf80+i*4);
        if(m.read_u8(row)<=m.read_u8(0x237f89))m.write_u32(work+4,total);
        m.write_u32(work+12+4*total,i);
        ++total;
    }
    m.write_u32(work+8,total);
    const auto focus=m.read_u32(work+4);m.write_u32(work,focus<8?0:focus-7);
}
void update_chapter_progress(GuestMemory& m,u32 label,std::uint64_t reason) {
    (void)run_vm_context(m,0x1af188,label,reason,0,0,nullptr);
}
void install_time_chart(GuestMemory& m,u32 arena,u32 capacity,std::span<const std::uint8_t> data) {
    constexpr std::string_view magic("SN4G tc ver4\0",13);
    if(!arena || capacity>GuestMemory::size || arena>GuestMemory::size-capacity || data.size()>capacity ||
       data.size()<18 || !std::equal(magic.begin(),magic.end(),data.begin()) || m.read_u32(0x2381b8))
        throw std::invalid_argument("1AC108 needs an unused workspace and the original SN4G time chart");
    u32 top=arena;
    auto alloc=[&](std::size_t n) {
        const auto start=(top+15)&~15u;
        if(start>arena+capacity || n>arena+capacity-start)throw std::runtime_error("1AC108 workspace exhausted");
        top=start+u32(n);return start;
    };
    const auto base=alloc(data.size());
    std::size_t pos=16;
    auto skip=[&](std::size_t n){
        if(pos>data.size() || n>data.size()-pos)throw std::runtime_error("Truncated 1AC108 chart section");
        pos+=n;
    };
    auto half=[&](){
        const auto at=pos;skip(2);return u32(data[at])|(u32(data[at+1])<<8);
    };
    auto addr=[&](){return base+u32(pos);};
    auto text_record=[&](){
        const auto p=addr();
        while(pos<data.size() && data[pos])++pos;
        skip(2);return p;
    };
    GuestMemory::Transaction tx(m);
    m.write_bytes(base,data);m.write_u32(0x2381b8,base);
    m.write_u32(0x238954,0);m.write_u32(0x23895c,0xffffffffu);m.write_u32(0x238958,0xffffffffu);
    m.write_u8(0x1e4bf18,0);
    m.write_u32(0x238ad8,0);m.write_u32(0x238adc,0xffffffffu); // 1007D8(6).
    const auto times=half();
    m.write_u32(0x238960,times);m.write_u32(0x238964,addr());skip(times*2);
    const auto strings=half(),pointers=alloc(strings*4);
    m.write_u32(0x238968,strings);m.write_u32(0x2381bc,pointers);
    for(u32 i=0;i<strings;++i)m.write_u32(pointers+i*4,text_record());
    const auto slots=half();m.write_u32(0x23896c,slots);m.write_u32(0x238970,addr());skip(slots*16);
    const auto labels=half();m.write_u32(0x238974,labels);m.write_u32(0x238978,addr());skip(labels*14);
    const auto aliases=half();m.write_u32(0x23897c,aliases);m.write_u32(0x238980,addr());skip(aliases*14);
    m.write_u32(0x238984,text_record());m.write_u32(0x238994,text_record());
    for(u32 i=0;i<4;++i)m.write_u32(0x1e4bf40+4*i,text_record());
    const auto groups=half();m.write_u32(0x238988,groups);
    if(groups>6)throw std::runtime_error("1AC108 group pointer capacity exceeded");
    for(u32 i=0;i<groups;++i){
        m.write_u32(0x1e4bf28+i*4,addr());
        const auto rows=half();skip(4);
        for(u32 j=0;j<rows;++j){
            const auto length=half();if(!length)throw std::runtime_error("Invalid 1AC108 group record");
            skip((length-1)*2);
        }
    }
    m.write_u32(0x23898c,addr());m.write_u32(0x238990,addr()+32);skip(64);
    for(u32 i=0;i<4;++i){
        const auto rows=half();m.write_u32(0x1e4bf50+i*4,rows);m.write_u32(0x1e4bf60+i*4,addr());
        for(u32 j=0;j<rows;++j){
            const auto pairs=half();skip(pairs*4);const auto parts=half();skip(parts*10);
        }
    }
    const auto bit_bytes=(labels+7)/8,bits=alloc(bit_bytes);
    m.write_u32(0x238998,labels);m.write_u32(0x23899c,bit_bytes);m.write_u32(0x2381c0,bits);
    m.write_bytes(bits,std::vector<std::uint8_t>(bit_bytes));
    m.write_u32(0x239e38+5*16,bit_bytes); // 1030A0(5, bytes) registers the original save area size.
    m.write_u32(0x2381c4,alloc((times+1)*88));m.write_u32(0x2381c8,alloc((times+1)*88));
    install_progress_callbacks(m,0x2319d0);
    m.write_u32(0x2381dc,alloc(32));m.write_u32(0x2381d0,1);
    m.write_u32(0x2381d4,0);m.write_u32(0x2381d8,0);m.write_u32(0x2381e0,0);
    tx.commit();
}
void update_time_chart_progress(GuestMemory& m,u32 label) {
    (void)run_vm_context(m,0x1ac598,label,0,0,0,nullptr);
}
namespace {
std::string chart_string(const GuestMemory& m,u32 p){
    std::string text;
    if(p)for(;m.read_u8(p);++p)text.push_back(char(m.read_u8(p)));
    return text;
}
}
TimeChartView visible_time_chart(const GuestMemory& m){
    TimeChartView view;
    if(!m.read_u32(0x2381d0) || !m.read_u32(0x2381d4))return view;
    const auto work=m.read_u32(0x2381dc),matrix=m.read_u32(0x2381c4),rows=m.read_u32(0x2389a0);
    view.actor=m.read_u32(work+8);view.row=m.read_u32(work+12);view.first_row=m.read_u32(work+4);
    if(rows>m.read_u32(0x238960)+1 || m.read_u32(0x2389a4)>4)
        throw std::runtime_error("Corrupt original time-chart dimensions");
    for(u32 a=0;a<4;++a)view.actors_cp932[a]=chart_string(m,m.read_u32(0x1e4bf40+4*a));
    for(u32 i=0;i<rows;++i) {
        const auto row=matrix+i*88;
        view.times.emplace_back(std::bit_cast<std::int32_t>(m.read_u32(row)),m.read_u32(row+4));
        for(u32 a=0;a<m.read_u32(0x2389a4);++a){
            const auto cell=row+8+a*20;
            if(!m.read_u32(cell+16))continue; // Original 1AD930 accessibility.
            const auto title=m.read_u32(cell+4);
            if(title>=m.read_u32(0x238968))throw std::runtime_error("Unrecognized chart title ID");
            view.available_cells.push_back({i,a,title,chart_string(m,m.read_u32(m.read_u32(0x2381bc)+title*4))});
        }
    }
    return view;
}
ChapterView visible_chapter_list(const GuestMemory& m){
    ChapterView view;
    if(!m.read_u32(0x238210)||!m.read_u32(0x238214))return view;
    const auto work=m.read_u32(0x238218),n=m.read_u32(work+8);
    if(n>max_entries)throw std::runtime_error("Corrupt source chapter list");
    view.first=m.read_u32(work);
    for(u32 i=0;i<n;++i){
        const auto id=m.read_u32(work+12+4*i);
        if(id>=m.read_u32(0x238204))throw std::runtime_error("Corrupt source chapter row");
        const auto record=m.read_u32(0x1e4bf80+id*4);
        view.rows.push_back({id,chart_string(m,record+14),m.read_u8(record)}); // 1AF2E0: LBU at 1AF310.
    }
    return view;
}
}
