#include "script_image.hpp"
#include "script_data.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace kx3 {
namespace {
using u32=std::uint32_t;
using namespace std::literals;
u32 word(std::span<const std::uint8_t> bytes,std::size_t at) {
    if(at>bytes.size() || bytes.size()-at<4) throw std::runtime_error("Truncated ScenarioLink/SCR word");
    return u32(bytes[at])|(u32(bytes[at+1])<<8)|(u32(bytes[at+2])<<16)|(u32(bytes[at+3])<<24);
}
bool prefix(std::span<const std::uint8_t> bytes,std::string_view text) {
    return bytes.size()>=text.size() && std::equal(text.begin(),text.end(),bytes.begin());
}
// Host validation runs before original mutating relocation functions. Enforce
// symbol-chain bounds and termination so malformed input cannot make the source
// walk an unbounded/cyclic list. Valid original source ordering is retained.
void validate(std::span<const std::uint8_t> bytes) {
    if(bytes.size()<0xa4 || !prefix(bytes,"ScenarioLink\0\0\0\0"sv) ||
       !prefix(bytes.subspan(16),":Ver:3.25.2.157\0"sv))
        throw std::runtime_error("Unsupported ScenarioLink data");
    const auto count=word(bytes,0xa0);
    if(count==0 || count>32 || 0xa4+count*8>bytes.size()) throw std::runtime_error("Unsupported ScenarioLink block count");
    std::size_t expected=0xa4+count*8;
    for(u32 i=0;i<count;++i) {
        const auto offset=word(bytes,0xa4+i*8), length=word(bytes,0xa8+i*8);
        if(offset!=expected || length<0x434 || offset>bytes.size() || length>bytes.size()-offset)
            throw std::runtime_error("Overlapping/truncated ScenarioLink block");
        const auto block=bytes.subspan(offset,length);
        if(!prefix(block,"SCR-file:Ver:3.25.2.157\0"sv)) throw std::runtime_error("Unsupported non-SCR block");
        const auto code=word(block,0x430);
        if(code<0x434 || code>length) throw std::runtime_error("Invalid SCR code boundary");
        std::vector<u32> records;
        for(u32 p=0x434;p<code;) {
            if(code-p<9) throw std::runtime_error("Truncated SCR symbol");
            const auto zero=std::find(block.begin()+p+8,block.begin()+code,0);
            if(zero==block.begin()+code || zero==block.begin()+p+8) throw std::runtime_error("Invalid SCR symbol name");
            const auto next=(u32(zero-block.begin())+4)&~3u;
            if(next>code) throw std::runtime_error("SCR symbol crosses code boundary");
            const auto link=u32(block[p])|(u32(block[p+1])<<8);
            if(link && link!=next-p) throw std::runtime_error("Unsupported SCR symbol link");
            const auto relative=word(block,p+4);
            if(relative>=length-code) throw std::runtime_error("SCR symbol target outside code");
            records.push_back(p); p=next;
        }
        std::vector<bool> visited(records.size(),false);
        for(u32 bucket=0;bucket<256;++bucket) {
            auto p=word(block,0x30+bucket*4);
            if(!p) continue;
            for(;;) {
                const auto record=std::lower_bound(records.begin(),records.end(),p);
                if(record==records.end() || *record!=p) throw std::runtime_error("SCR bucket/link is not a symbol boundary");
                const auto index=std::size_t(record-records.begin());
                if(visited[index]) throw std::runtime_error("Duplicate SCR bucket chain");
                visited[index]=true;
                const auto link=u32(block[p])|(u32(block[p+1])<<8);
                if(!link) break;
                p+=link;
            }
        }
        if(std::find(visited.begin(),visited.end(),false)!=visited.end())
            throw std::runtime_error("SCR symbol is absent from bucket chains");
        expected=std::size_t(offset)+length;
    }
    if(expected!=bytes.size()) throw std::runtime_error("Unexpected ScenarioLink trailing data");
}
}

ScriptImageIndex load_script_index(GuestMemory& m,std::span<const std::uint8_t> bytes,u32 begin,u32 end) {
    validate(bytes);
    if(begin>end || end>GuestMemory::size) throw std::runtime_error("Invalid reserved script-index arena");
    u32 cursor=begin;
    auto allocate=[&](std::size_t length) {
        const auto aligned=(std::uint64_t(cursor)+63)&~std::uint64_t(63);
        if(aligned>end || length>std::uint64_t(end)-aligned) throw std::runtime_error("Reserved script-index arena exhausted");
        cursor=u32(aligned+length); return u32(aligned);
    };
    GuestMemory::AccessBudget budget(m,8'000'000);
    GuestMemory::Transaction transaction(m);
    const u32 self=allocate(0x188), image=allocate(bytes.size());
    m.write_bytes(image,bytes); m.write_u32(self+4,image);
    //10CFE8 actual source: LBU count, writeC4, then relative block pointers.
    const u32 count=m.read_u8(image+0xa0);
    m.write_u32(self+0xc4,count);
    for(u32 i=0;i<count;++i) m.write_u32(self+8+i*4,image+m.read_u32(image+0xa4+i*8));
    (void)invoke_script_data(m,0x0010f678,self,0,0);
    (void)invoke_script_data(m,0x0010f6e0,self,0,0);
    const auto labels=m.read_u32(self+0xc8);
    if(labels>0xffff) throw std::runtime_error("Source label IDs exceed u16 space");
    //10F768's platform allocation is supplied by the reserved native arena.
    const auto table=allocate(std::size_t(labels)*4);
    m.write_u32(self+0xcc,table);
    for(u32 i=0;i<count;++i) {
        const auto block=m.read_u32(self+8+i*4);
        for(u32 bucket=0;bucket<256;++bucket) {
            auto symbol=m.read_u32(block+0x30+bucket*4);
            if(!symbol) continue;
            for(;;) {
                const auto id=m.read_u16(symbol+2);
                if(id!=0xffff) {
                    if(id>=labels) throw std::runtime_error("Source label index outside allocation");
                    m.write_u32(table+u32(id)*4,symbol);
                }
                const auto link=m.read_u16(symbol);
                if(!link) break;
                symbol+=link;
            }
        }
    }
    transaction.commit();
    return {self,image,count,labels,table,cursor};
}
}
