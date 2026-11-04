#include "pss_audio.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <stdexcept>

namespace kx3 {
namespace {
using u8=std::uint8_t;
using u32=std::uint32_t;
using u64=std::uint64_t;
using Bytes=std::span<const u8>;
void require(bool condition,const char* message){if(!condition)throw std::runtime_error(message);}
u32 le32(Bytes b,std::size_t i) {
    return u32(b[i])|(u32(b[i+1])<<8)|(u32(b[i+2])<<16)|(u32(b[i+3])<<24);
}
u64 timestamp(Bytes p,u8 prefix) {
    require(p.size()>=5 && p[0]>>4==prefix && (p[0]&1) && (p[2]&1) && (p[4]&1),"Invalid PSS presentation timestamp");
    return (u64((p[0]>>1)&7)<<30)|(u64(p[1])<<22)|(u64(p[2]>>1)<<15)|(u64(p[3])<<7)|(p[4]>>1);
}
}

std::optional<PssPcm> decode_pss_audio(Bytes stream) {
    std::vector<u8> ads;
    std::optional<u64> audio_pts,video_pts;
    bool end=false;
    while(!stream.empty()) {
        require(stream.size()>=4 && !stream[0] && !stream[1] && stream[2]==1,"Invalid original PSS packet boundary");
        const auto type=stream[3];
        if(type==0xb9){require(stream.size()==4,"Data after PSS program end");end=true;break;}
        if(type==0xba) {
            require(stream.size()>=14 && (stream[4]&0xc0)==0x40,"Unsupported PSS pack header");
            const auto size=14u+(stream[13]&7);
            require(size<=stream.size(),"Truncated PSS pack stuffing");stream=stream.subspan(size);continue;
        }
        require(stream.size()>=6,"Truncated PSS packet");
        const auto size=(u32(stream[4])<<8)|stream[5];
        require(size && size<=stream.size()-6,"Invalid PSS packet length");
        auto packet=stream.subspan(6,size);stream=stream.subspan(6+size);
        if(type==0xbb || type==0xbe)continue; // System header and padding.
        require(type==0xbd || type==0xe0,"Unrecognized original PSS elementary stream");
        require(packet.size()>=3 && (packet[0]&0xc0)==0x80 && packet[2]<=packet.size()-3,"Invalid PSS PES header");
        const auto flags=packet[1]>>6;
        require(flags!=1,"Invalid PSS PTS/DTS flags");
        if(flags) {
            const auto pts=timestamp(packet.subspan(3,packet[2]),flags);
            auto& first=type==0xbd?audio_pts:video_pts;
            if(!first)first=pts;
        }
        if(type==0xe0)continue;
        const auto payload=packet.subspan(3+packet[2]);
        constexpr std::array<u8,4> substream{0xff,0xa0,0,0};
        require(payload.size()>=4 && std::equal(substream.begin(),substream.end(),payload.begin()),
                "Unknown PSS private audio substream");
        ads.insert(ads.end(),payload.begin()+4,payload.end());
    }
    require(end,"Missing PSS program end");
    if(ads.empty())return std::nullopt;
    const Bytes bytes(ads);
    // Every original audio-bearing PSS uses the same Sony ADS variant.
    // SShd contains 24 bytes, SSbd carries alternating 512-byte L/R planes.
    require(audio_pts && video_pts && bytes.size()>=40 && le32(bytes,0)==0x64685353 &&
            le32(bytes,4)==24 && le32(bytes,8)==1 && le32(bytes,12)==48000 && le32(bytes,16)==2 &&
            le32(bytes,20)==512 && le32(bytes,24)==0xffffffff && le32(bytes,28)==0xffffffff &&
            le32(bytes,32)==0x64625353,"Unsupported or incomplete original PSS audio header");
    const auto pcm=bytes.subspan(40);
    require(pcm.size()==le32(bytes,36) && pcm.size()%1024==0,"Truncated or misaligned PSS stereo block");
    PssPcm result;
    result.rate=le32(bytes,12);result.channels=le32(bytes,16);
    result.first_audio_pts90k=*audio_pts;result.first_video_pts90k=*video_pts;
    constexpr u64 cycle=u64(1)<<33;
    result.audio_offset90k=std::int64_t((*audio_pts-*video_pts+cycle/2)&(cycle-1))-std::int64_t(cycle/2);
    result.interleaved.resize(pcm.size()/2);
    for(std::size_t block=0;block<pcm.size();block+=1024) {
        for(std::size_t sample=0;sample<256;++sample) {
            for(unsigned channel=0;channel<2;++channel) {
                const auto at=block+channel*512+2*sample;
                const auto value=std::uint16_t(pcm[at]|(std::uint16_t(pcm[at+1])<<8));
                result.interleaved[block/2+2*sample+channel]=std::bit_cast<std::int16_t>(value);
            }
        }
    }
    return result;
}
}
