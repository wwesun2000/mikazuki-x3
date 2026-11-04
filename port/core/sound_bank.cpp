#include "sound_bank.hpp"
#include <algorithm>
#include <array>
#include <stdexcept>

namespace kx3 {
namespace {
using u32=std::uint32_t;
u32 word(std::span<const std::uint8_t> s,std::size_t p) {
    return u32(s[p])|u32(s[p+1])<<8|u32(s[p+2])<<16|u32(s[p+3])<<24;
}
}
std::optional<SoundRecord> find_bank_sound(std::span<const std::uint8_t> bank,u32 id) {
    if(bank.size()<57344) throw std::runtime_error("Incomplete SE index");
    for (unsigned i=0;i<1000;++i) {
        auto row=bank.subspan(56*i,56);
        if (!(row[0]&128)) break; // original 1D1BF8 table termination
        u32 key=0;
        for(unsigned digit=40;digit<46;++digit) {
            if(row[digit]<'0'||row[digit]>'9')throw std::runtime_error("Invalid SE name");
            key=key*10+(row[digit]-'0');
        }
        if(key!=id)continue;
        const auto offset=std::uint64_t(word(row,4))*2048, extent=std::uint64_t(word(row,8))*2048;
        const auto total=std::uint64_t(word(row,12))*2, stride=std::uint64_t(word(row,16))*2;
        if(row[46] || offset<57344 || offset+extent>bank.size() || total>extent || !stride ||
           (total|stride)%16 || total/stride<1 || total/stride>2 || total%stride>48)
            throw std::runtime_error("Invalid original SE allocation");
        return SoundRecord{u32(offset),u32(extent),u32(stride),std::uint16_t(row[36]|row[37]<<8),
            std::uint16_t(row[38]|row[39]<<8),std::uint8_t(total/stride),row[3],{row[54],row[55]}};
    }
    return std::nullopt;
}

SoundPcm decode_bank_channel(std::span<const std::uint8_t> bank,const SoundRecord& r,unsigned channel) {
    const auto address=std::uint64_t(r.offset)+std::uint64_t(channel)*r.stream_bytes;
    if(channel>=r.channels || r.stream_bytes%16 || address+r.stream_bytes>bank.size())
        throw std::runtime_error("SE channel exceeds original allocation");
    const auto data=bank.subspan(std::size_t(address),r.stream_bytes);
    constexpr std::array<std::array<int,2>,5> filters{{{0,0},{60,0},{115,-52},{98,-55},{122,-60}}};
    SoundPcm out;
    out.samples.reserve(data.size()/16*28);
    std::int64_t prev=0,older=0;
    for(std::size_t p=0;p<data.size();p+=16) {
        const unsigned filter=data[p]>>4,shift=data[p]&15,flags=data[p+1];
        if(filter>=filters.size() || shift>12 || flags>7)throw std::runtime_error("Invalid PSX ADPCM block");
        if(flags&4)out.loop_start=u32(out.samples.size());
        for(unsigned i=0;i<28;++i) {
            const int n=(data[p+2+i/2]>>((i&1)*4))&15;
            const int residual=(n>=8?n-16:n)*(4096>>shift);
            const auto predicted=(prev*filters[filter][0]+older*filters[filter][1])/64;
            const auto sample=residual+predicted;
            older=prev;prev=sample;
            out.samples.push_back(static_cast<std::int16_t>(std::clamp<std::int64_t>(sample,-32768,32767)));
        }
        if(flags&1) {
            if(bool(flags&2)!=bool(r.flags&16) || ((flags&2) && !out.loop_start))
                throw std::runtime_error("Inconsistent original ADPCM loop");
            if(!(flags&2))out.loop_start.reset();
            return out;
        }
    }
    throw std::runtime_error("Original ADPCM channel has no end block");
}
}
