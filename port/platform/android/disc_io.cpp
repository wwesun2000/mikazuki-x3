#include "android_host.hpp"
#include "../windows/raster_loader.hpp"
#include "../../core/retail_disc.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <mutex>
#include <fstream>
#include <cerrno>
#include <system_error>
extern "C" {
#include <libavutil/sha.h>
#include <libavutil/mem.h>
}

namespace {
std::mutex disc_mutex;
int owned_fd=-1;
std::unique_ptr<kx3::RetailDisc> disc;
}
namespace kx3::platform::windows {
std::string source_bytes_sha256(std::span<const std::uint8_t> bytes) {
    AVSHA* sha=av_sha_alloc();
    if(!sha)throw std::bad_alloc();
    av_sha_init(sha,256);av_sha_update(sha,bytes.data(),bytes.size());
    unsigned char result[32];av_sha_final(sha,result);av_free(sha);
    constexpr char digits[]="0123456789abcdef";std::string text; text.reserve(64);
    for(auto b:result){text+=digits[b>>4];text+=digits[b&15];}return text;
}
std::filesystem::path game_disc_path(const std::filesystem::path&) {
    if(owned_fd<0)throw std::runtime_error("Choose the original game ISO first");
    return "/proc/self/fd/"+std::to_string(owned_fd);
}
std::uint64_t disc_resource_size(const std::filesystem::path&,std::string_view member){
    std::lock_guard lock(disc_mutex);
    if(!disc)throw std::runtime_error("Game ISO is not mounted");return disc->member_size(member);
}
std::vector<std::uint8_t> read_disc_resource(const std::filesystem::path&,std::string_view name,const std::string& hash,std::uint64_t size){
    std::vector<std::uint8_t> bytes;
    {std::lock_guard lock(disc_mutex);if(!disc)throw std::runtime_error("Game ISO is not mounted");bytes=disc->read(name,size);}
    if(source_bytes_sha256(bytes)!=hash)throw std::runtime_error("ISO resource hash mismatch: "+std::string(name));
    return bytes;
}
std::vector<std::uint8_t> read_verified_source(const std::filesystem::path& path,const std::string& hash,std::uint64_t size){
    if(!size || size>64ull*1024*1024)throw std::runtime_error("Invalid source length");
    std::ifstream f(path,std::ios::binary|std::ios::ate);
    if(!f || f.tellg()!=std::streamoff(size))throw std::runtime_error("Source length mismatch");
    std::vector<std::uint8_t> b(size);f.seekg(0);f.read(reinterpret_cast<char*>(b.data()),size);
    if(!f || source_bytes_sha256(b)!=hash)throw std::runtime_error("Source hash mismatch");return b;
}
void verify_encoded_source(const std::filesystem::path& p,const std::string& h,std::uint64_t n){(void)read_verified_source(p,h,n);}
}
namespace kx3::platform::android {
void mount_disc_fd(int fd){
    const int next=fcntl(fd,F_DUPFD_CLOEXEC,0);
    if(next<0)throw std::runtime_error("Cannot retain the selected ISO");
    try{
        if(lseek(next,0,SEEK_END)!=3594551296LL)throw std::runtime_error("Choose the uncompressed SLPM-66452 ISO on local device storage (3,594,551,296 bytes)");
        auto read=[next](std::uint64_t offset,std::span<std::uint8_t> bytes){
            std::size_t done=0;
            while(done<bytes.size()){
                const auto count=pread(next,bytes.data()+done,bytes.size()-done,off_t(offset+done));
                if(count<0){if(errno==EINTR)continue;throw std::system_error(errno,std::generic_category(),"Read selected game ISO");}
                if(!count)throw std::runtime_error("Incomplete read from selected game ISO");
                done+=std::size_t(count);
            }
        };
        auto candidate=std::make_unique<RetailDisc>(read,3594551296ULL,windows::source_bytes_sha256);
        std::lock_guard lock(disc_mutex);disc=std::move(candidate);
        if(owned_fd>=0)close(owned_fd);owned_fd=next;
    }catch(...){close(next);throw;}
}
void unmount_disc(){std::lock_guard lock(disc_mutex);disc.reset();if(owned_fd>=0)close(owned_fd);owned_fd=-1;}
std::string mounted_disc_path(){return windows::game_disc_path({}).string();}
}
