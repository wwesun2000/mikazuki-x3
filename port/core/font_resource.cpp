#include "font_resource.hpp"
#include <algorithm>
#include <string_view>

namespace kx3 {
FontResourceResult install_font_resource(GuestMemory& m,std::uint32_t base,std::span<const std::uint8_t> file) {
    constexpr std::uint32_t cell=0x236f30; // ELF gp - 27584.
    constexpr std::string_view magic="SN4Font:V.1.4.";
    if(file.size()<28 || file.size()>GuestMemory::size || !std::equal(magic.begin(),magic.end(),file.begin()))
        throw std::invalid_argument("Expected a complete SN4Font V1.4 resource");
    if(!base || (base&3) || base>GuestMemory::size-file.size() || (base<cell+4 && base+file.size()>cell))
        throw std::out_of_range("Invalid reserved font allocation");
    const auto word=[&](std::size_t offset) {
        if(offset>file.size()-4) throw std::invalid_argument("Truncated font field");
        return std::uint32_t(file[offset]) | (std::uint32_t(file[offset+1])<<8)
             | (std::uint32_t(file[offset+2])<<16) | (std::uint32_t(file[offset+3])<<24);
    };
    const auto groups=word(24);
    if(!groups || groups>4096) throw std::invalid_argument("Invalid font group count");
    // Validate file-controlled boundaries before following the original chain.
    std::uint32_t group=28,total=0,first_payload=std::uint32_t(file.size());
    for(std::uint32_t i=0;i<groups;++i) {
        if(group>file.size()-20)throw std::invalid_argument("Truncated font group");
        const auto count=word(group+12),next=word(group+16);
        if(!count || count>65536 || count>(file.size()-group-20)/12)throw std::invalid_argument("Invalid font glyph table");
        const auto end=group+20+12*count;
        if(next!=(i+1<groups?end:0u))throw std::invalid_argument("Invalid font descriptor chain");
        for(std::uint32_t at=group+20;at<end;at+=12) {
            const auto payload=word(at+8);
            if(payload>=file.size())throw std::invalid_argument("Font glyph payload outside file");
            first_payload=std::min(first_payload,payload);
        }
        total+=count;group=end;
    }
    if(first_payload<group)throw std::invalid_argument("Font glyph payload overlaps descriptor tables");
    GuestMemory::Transaction tx(m);
    m.write_bytes(base,file);
    m.write_u32(cell,base);
    // 16BD88 loops through the file-relative group links and relocates only
    // the payload at glyph+8. The group links themselves stay relative.
    group=base+28;
    for(std::uint32_t i=0;i<groups;++i) {
        const auto count=m.read_u32(group+12);
        for(std::uint32_t j=0;j<count;++j) {
            const auto field=group+20+j*12+8;
            m.write_u32(field,base+m.read_u32(field));
        }
        group=base+m.read_u32(group+16);
    }
    tx.commit();
    return {base,groups,total};
}

void initialize_native_font_palette(GuestMemory& memory) {
    constexpr std::uint32_t palette=0x1e44180;
    const auto source_default=memory.read_u32(0x236f38);
    GuestMemory::Transaction tx(memory);
    for(unsigned index=0;index<16;++index)memory.write_u32(palette+4*index,source_default);
    memory.write_u32(palette,0);
    for(unsigned index=1;index<15;++index) {
        const unsigned step=index<8?index-1:index-8;
        const std::uint32_t gray=step*255/7;
        const std::uint32_t alpha=index<8?128:88;
        memory.write_u32(palette+4*index,(alpha<<24)|(gray<<16)|(gray<<8)|gray);
    }
    tx.commit();
}
}
