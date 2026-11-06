#pragma once
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace kx3 {
// Read-only ISO9660 and main FAD bank for the supported Japanese edition.
class RetailDisc {
public:
    // SAF grants an open descriptor, not permission to reopen its filesystem
    // path. The caller owns that descriptor and supplies bounded random reads.
    using ReadAt=std::function<void(std::uint64_t,std::span<std::uint8_t>)>;
private:
    using Bytes=std::vector<std::uint8_t>;
    using Digest=std::string(*)(std::span<const std::uint8_t>);
    struct Extent {std::uint64_t offset,size;};
    std::ifstream stream_;
    ReadAt reader_;
    std::map<std::string,Extent,std::less<>> resources_;
    static constexpr std::uint64_t sector=2048, disc_bytes=3594551296;
    static std::uint32_t le32(const std::uint8_t* p){
        return p[0]|std::uint32_t(p[1])<<8|std::uint32_t(p[2])<<16|std::uint32_t(p[3])<<24;
    }
    Bytes read_at(Extent e){
        if(e.offset>disc_bytes || e.size>disc_bytes-e.offset)throw std::runtime_error("ISO extent outside disc");
        Bytes bytes(static_cast<std::size_t>(e.size));
        if(reader_){reader_(e.offset,bytes);return bytes;}
        stream_.clear();
        if(!stream_.seekg(e.offset) || !stream_.read(reinterpret_cast<char*>(bytes.data()),bytes.size()))
            throw std::runtime_error("Incomplete read from game ISO");
        return bytes;
    }
    static std::string name(const std::uint8_t* p,unsigned n){
        unsigned len=0;while(len<n && p[len])++len;
        while(len && p[len-1]==' ')--len;
        return std::string(reinterpret_cast<const char*>(p),len);
    }
public:
    RetailDisc(const std::filesystem::path& iso,Digest digest):stream_(iso,std::ios::binary|std::ios::ate){
        if(!stream_)throw std::runtime_error("Game ISO could not be opened: "+iso.string());
        if(stream_.tellg()!=std::streamoff(disc_bytes))throw std::runtime_error("Incorrect game ISO size");
        initialize(digest);
    }
    RetailDisc(ReadAt reader,std::uint64_t size,Digest digest):reader_(std::move(reader)){
        if(!reader_ || size!=disc_bytes)throw std::runtime_error("Incorrect game ISO size or reader");
        initialize(digest);
    }
private:
    void initialize(Digest digest){
        auto pvd=read_at({16*sector,sector});
        if(digest(pvd)!="b4a960a329d1ee99152a93d824192f46312abbdd2b04a1652fdb9fca650f6ba9")
            throw std::runtime_error("Unsupported ISO volume (expected SLPM-66452)");
        const auto root=read_at({sector*le32(&pvd[158]),le32(&pvd[166])});
        if(digest(root)!="e1bb0537d834fae831dabea9a77ba4cf4ef346168f6b31653bde5cf759782d38")
            throw std::runtime_error("Incorrect ISO root directory");
        std::map<std::string,Extent> files;
        for(std::size_t pos=0;pos<root.size();pos+=root[pos]){
            const auto* r=root.data()+pos;
            if(!r[0] || r[0]>root.size()-pos || r[0]<34 || 33u+r[32]>r[0])throw std::runtime_error("Invalid ISO record");
            if(r[25]&2)continue;
            auto key=name(r+33,r[32]);
            if(key.ends_with(";1"))key.resize(key.size()-2);
            files.emplace(key,Extent{sector*le32(r+2),le32(r+10)});
        }
        resources_.emplace("SLPM_664.52",files.at("SLPM_664.52"));
        const auto fad=files.at("DISC.FAD");
        const auto end=files.at("DISC4.FAD").offset;
        const auto index=read_at(fad);
        if(digest(index)!="4833294c34db59b16291bda2985afe9e9c371748a38ebb9c0aeea2fd9c1dd8f1")
            throw std::runtime_error("Incorrect original DISC.FAD index");
        // These identity-checked records contain parent indices, including forward references.
        for(std::size_t pos=0;pos+32<=index.size();pos+=32){
            const auto* r=index.data()+pos;
            if(le32(r)!=0 || !r[4])continue;
            auto key=name(r+4,8)+"."+name(r+12,3);
            auto parent=le32(r+24);
            while(parent!=UINT32_MAX){
                const auto* dir=index.data()+32*std::size_t(parent);
                key=name(dir+4,12)+"/"+key;parent=le32(dir+24);
            }
            const Extent e{fad.offset+sector*le32(r+20),le32(r+16)};
            if(e.offset>end || e.size>end-e.offset || !resources_.emplace(key,e).second)
                throw std::runtime_error("Invalid main FAD file: "+key);
        }
    }
public:
    std::uint64_t member_size(std::string_view key) const {
        const auto it=resources_.find(key);
        if(it==resources_.end())throw std::runtime_error("Unknown disc resource: "+std::string(key));
        return it->second.size;
    }
    Bytes read(std::string_view key,std::uint64_t size){
        const auto it=resources_.find(key);
        if(it==resources_.end() || it->second.size!=size)throw std::runtime_error("Unknown or mismatched disc resource: "+std::string(key));
        return read_at(it->second);
    }
};
}
