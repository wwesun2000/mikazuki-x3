#include "choice_presentation.hpp"
#include <algorithm>
#include <bit>

namespace kx3 {
namespace {
using u32=std::uint32_t;
struct Nodes {u32 base,count;};
Nodes channel_nodes(const GuestMemory& m,u32 font,unsigned channel) {
    if(channel>1) throw std::runtime_error("Unknown font channel");
    const u32 pool=m.read_u32(m.read_u32(font+8+4*channel));
    const u32 count=m.read_u32(pool+4),base=m.read_u32(pool+8);
    if(count>m.read_u32(pool) || count>(channel?100u:400u))
        throw std::runtime_error("Source glyph pool count exceeds capacity");
    if(count) (void)m.bytes(base,count*56);
    return {base,count};
}
void validate_range(Nodes nodes,int first,int last) {
    if(first<0 || last<first-1 || last>=int(nodes.count))
        throw std::runtime_error("Choice references inactive glyph nodes");
}
}

std::optional<u32> source_choice_at(const GuestMemory& m,u32 manager,int x,int y) {
    if(x<0 || x>=640 || y<0 || y>=448) return {};
    const u32 context=m.read_u32(manager+0x40);
    if(m.read_u32(m.read_u32(context))!=0x11e748) return {};
    const u32 choice=m.read_u32(manager+8),count=m.read_u32(choice+4);
    if(m.read_u32(choice+0xc)!=1 || !count || count>10) return {};
    const auto nodes=channel_nodes(m,m.read_u32(manager+0x3c),0);
    for(u32 option=0;option<count;++option) {
        const auto first=std::bit_cast<std::int32_t>(m.read_u32(choice+0xc8+option*4));
        const auto last=std::bit_cast<std::int32_t>(m.read_u32(choice+0xf0+option*4));
        validate_range(nodes,first,last);
        // Join glyph boxes on the same line, including internal spaces, but
        // exclude whitespace to the right of short or wrapped answers.
        int left=640,right=0;
        for(int i=first;i<=last;++i) {
            const u32 node=nodes.base+56*u32(i);
            const int top=std::bit_cast<std::int32_t>(m.read_u32(node+16));
            const int bottom=std::bit_cast<std::int32_t>(m.read_u32(node+24));
            if(y<top || y>=bottom) continue;
            left=std::min(left,int(std::bit_cast<std::int32_t>(m.read_u32(node+12))));
            right=std::max(right,int(std::bit_cast<std::int32_t>(m.read_u32(node+20))));
        }
        if(x>=left && x<right) return option;
    }
    return {};
}

}
