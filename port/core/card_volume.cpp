#include "card_volume.hpp"
#include "save.hpp"
#include "save_lock.hpp"
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <fstream>
#include <string_view>
#include <stdexcept>

namespace kx3 {
namespace {
using u32=std::uint32_t;
constexpr u32 capacity=8192; // KiB-sized clusters available on this virtual medium.
bool valid_key(const std::string& key){
    const auto slash=key.find('/');
    if(slash==std::string::npos || !slash || slash+1==key.size() || slash!=key.rfind('/') || key.size()>80)return false;
    return key.substr(0,slash)!="." && key.substr(slash+1)!="." && key.find("..")==std::string::npos && key.find_first_not_of(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_/.-")==std::string::npos;
}
bool matches(const std::string& pattern,const std::string& name){
    const auto star=pattern.find('*');
    if(star==std::string::npos)return pattern==name;
    if(pattern.find('*',star+1)!=std::string::npos)throw std::invalid_argument("Unsupported card wildcard");
    return name.size()>=pattern.size()-1 && name.starts_with(pattern.substr(0,star)) &&
           name.ends_with(pattern.substr(star+1));
}
template<class Files> std::uint64_t used_clusters(const Files& files){
    std::uint64_t used=0;
    for(const auto& [key,file]:files)used+=(file.bytes.size()+1023)/1024;
    return used;
}
constexpr std::string_view magic="KX3CARD1";
}
CardVolume::Files CardVolume::read_volume(const std::filesystem::path& root){
    Files files;
    if(root.empty() || !std::filesystem::exists(root/"card.bin"))return files;
    std::ifstream in(root/"card.bin",std::ios::binary);
    if(!in)throw std::system_error(errno?errno:EIO,std::generic_category(),"Open memory card volume");
    char hdr[8];
    if(!in.read(hdr,8) || std::string_view(hdr,8)!=magic)throw std::runtime_error("Invalid card volume");
    auto number=[&](unsigned width){
        std::uint64_t v=0;
        for(unsigned i=0;i<width;++i){const int c=in.get();if(c<0)throw std::runtime_error("Truncated card volume");v|=std::uint64_t(c)<<(8*i);}
        return v;
    };
    const auto count=number(4);
    if(count>capacity)throw std::runtime_error("Invalid card file count");
    std::uint64_t used=0;
    for(unsigned i=0;i<count;++i){
        const auto length=number(1),size=number(4),time=number(8);
        if(!length || length>80 || !size || size>capacity*1024 || (used+=(size+1023)/1024)>capacity ||
           time>253402300799ull)throw std::runtime_error("Invalid card file header");
        std::string key(length,'\0');
        if(!in.read(key.data(),length) || !valid_key(key) || files.contains(key))throw std::runtime_error("Invalid card path");
        File entry{std::vector<std::uint8_t>(size),std::int64_t(time)};
        if(!in.read(reinterpret_cast<char*>(entry.bytes.data()),size))throw std::runtime_error("Truncated card file");
        files.emplace(std::move(key),std::move(entry));
    }
    if(in.peek()!=EOF)throw std::runtime_error("Trailing card volume data");
    return files;
}
void CardVolume::mount(std::filesystem::path root){
    auto contents=read_volume(root);files_.swap(contents);root_=std::move(root);pending_.clear();
}
std::vector<CardFileEntry> CardVolume::enumerate(const std::string& pattern) const{
    const auto slash=pattern.find('/');
    const auto leaf=slash==std::string::npos?pattern:pattern.substr(slash+1);
    std::map<std::string,CardFileEntry> seen;
    std::vector<CardFileEntry> out;
    auto collect=[&](const auto& files){for(const auto& [key,file]:files){
        const auto split=key.find('/');
        const auto dir=key.substr(0,split);
        const bool directory=slash==std::string::npos;
        if(!directory && dir!=pattern.substr(0,slash))continue;
        const auto name=directory?dir:key.substr(split+1);
        if(matches(leaf,name)){
            auto& row=seen[name];
            row={name,directory,directory?0u:static_cast<u32>(file.bytes.size()),std::max(row.modified,file.modified)};
        }
    }};
    collect(files_);collect(pending_);
    for(auto& [name,row]:seen)out.push_back(std::move(row));
    return out;
}
const std::vector<std::uint8_t>* CardVolume::read(const std::string& key) const{
    if(auto it=pending_.find(key);it!=pending_.end())return &it->second.bytes;
    const auto it=files_.find(key);
    return it==files_.end()?nullptr:&it->second.bytes;
}
u32 CardVolume::free_clusters() const{
    auto used=used_clusters(files_);
    for(const auto& [key,f]:pending_){
        if(auto it=files_.find(key);it!=files_.end())used-=(it->second.bytes.size()+1023)/1024;
        used+=(f.bytes.size()+1023)/1024;
    }
    return capacity-u32(used);
}
bool CardVolume::stage_file(std::string key,std::span<const std::uint8_t> bytes,bool create){
    if(!valid_key(key) || bytes.empty())throw std::invalid_argument("Invalid memory card file");
    const auto* old=read(key);
    if(!old && !create)return false;
    const auto clusters=(bytes.size()+1023)/1024;
    if(clusters>free_clusters()+(old?(old->size()+1023)/1024:0))return false;
    const auto now=std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()).time_since_epoch().count();
    pending_[std::move(key)]={{bytes.begin(),bytes.end()},now};
    return true;
}
void CardVolume::commit_writes(bool preserve_existing) try {
    if(pending_.empty())return;
    Files next;
    if(!root_.empty()){
        std::filesystem::create_directories(root_);
        SaveWriterLock lock(root_/"writer.lock","Memory card is busy");
        next=read_volume(root_);
        for(const auto& [key,file]:pending_){
            const auto old=files_.find(key),current=next.find(key);
            if((old==files_.end())!=(current==next.end()) ||
               (old!=files_.end() && old->second.bytes!=current->second.bytes))
                throw std::runtime_error("Memory card slot changed in another session");
            if(preserve_existing && current!=next.end() && current->second.bytes!=file.bytes)
                throw std::runtime_error("New game would replace an existing memory card record");
            next[key]=file;
        }
        if(used_clusters(next)>capacity)throw std::runtime_error("Memory card full");
        std::vector<std::uint8_t> image(magic.begin(),magic.end());
        auto number=[&](std::uint64_t v,unsigned width){for(unsigned i=0;i<width;++i)image.push_back(std::uint8_t(v>>(8*i)));};
        number(next.size(),4);
        for(const auto& [key,file]:next){
            number(key.size(),1);number(file.bytes.size(),4);number(file.modified,8);
            image.insert(image.end(),key.begin(),key.end());image.insert(image.end(),file.bytes.begin(),file.bytes.end());
        }
        replace_save_file_atomic(root_/"card.bin",image);
    }else{
        next=files_;
        for(const auto& [key,file]:pending_)next[key]=file;
    }
    files_.swap(next);
    pending_.clear();
}catch(const std::system_error& error){
    throw CardWriteError(error);
}
void CardVolume::set_icon(std::string name,std::vector<std::uint8_t> bytes){icons_[std::move(name)]=std::move(bytes);}
const std::vector<std::uint8_t>& CardVolume::icon(const std::string& name) const{
    const auto i=icons_.find(name);
    if(i==icons_.end())throw std::runtime_error("Missing ISO card icon "+name);
    return i->second;
}
}
