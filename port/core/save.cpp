#include "save.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <fstream>
#include <string>
#include <system_error>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace kx3 {
namespace {
constexpr std::uint32_t page_size = 4096;
constexpr std::uint32_t pages = GuestMemory::size / page_size;
constexpr std::size_t max_size = GuestMemory::size + pages * 4 + 128;
constexpr std::array<std::uint8_t, 8> magic{'K','X','3','S','A','V','E',0};
void append(std::vector<std::uint8_t>& out, std::uint64_t n, unsigned width) {
    for (unsigned i=0; i<width; ++i) out.push_back(std::uint8_t(n >> (8*i)));
}
std::uint64_t take(std::span<const std::uint8_t> data, std::size_t& pos, unsigned width) {
    if (pos > data.size() || width > data.size()-pos) throw std::runtime_error("Truncated core checkpoint");
    std::uint64_t n=0;
    for (unsigned i=0; i<width; ++i) n |= std::uint64_t(data[pos++]) << (8*i);
    return n;
}
std::uint32_t crc32(std::span<const std::uint8_t> data) {
    std::uint32_t crc=0xffffffffu;
    for (auto b:data) {
        crc ^= b;
        for (unsigned i=0;i<8;++i) crc=(crc>>1)^(0xedb88320u & (0u-(crc&1u)));
    }
    return ~crc;
}
bool nonzero(std::span<const std::uint8_t> data) {
    return std::any_of(data.begin(), data.end(), [](auto b){return b!=0;});
}
void check_identity(const SaveIdentity& id) {
    if (!nonzero(id.executable_sha256) || !nonzero(id.assets_sha256) || !id.core_abi_revision)
        throw std::runtime_error("A checkpoint requires explicit executable/assets identities and ABI revision");
}
}

std::vector<std::uint8_t> encode_checkpoint(const CoreCheckpoint& state, const SaveIdentity& id) {
    check_identity(id);
    if (state.memory.transaction_active()) throw std::runtime_error("Checkpoint requested during a partial native step");
    (void)state.memory.bytes(state.manager, state.manager ? 0x858 : 0);
    std::vector<std::uint32_t> occupied;
    for (std::uint32_t i=0;i<pages;++i)
        if (nonzero(state.memory.bytes(i*page_size,page_size))) occupied.push_back(i);
    std::vector<std::uint8_t> out(magic.begin(),magic.end());
    out.reserve(128+occupied.size()*(page_size+4));
    append(out,1,4); append(out,GuestMemory::size,4); append(out,page_size,4);
    append(out,id.core_abi_revision,4);
    out.insert(out.end(),id.executable_sha256.begin(),id.executable_sha256.end());
    out.insert(out.end(),id.assets_sha256.begin(),id.assets_sha256.end());
    append(out,state.manager,4); append(out,state.logical_tick,8); append(out,occupied.size(),4);
    for(auto i:occupied) {
        append(out,i,4);
        const auto bytes=state.memory.bytes(i*page_size,page_size);
        out.insert(out.end(),bytes.begin(),bytes.end());
    }
    append(out,crc32(out),4);
    return out;
}

CoreCheckpoint decode_checkpoint(std::span<const std::uint8_t> data, const SaveIdentity& expected) {
    check_identity(expected);
    if (data.size()<108 || data.size()>max_size || !std::equal(magic.begin(),magic.end(),data.begin()))
        throw std::runtime_error("Invalid core checkpoint framing");
    std::size_t checksum_pos=data.size()-4;
    const auto expected_crc=take(data,checksum_pos,4);
    if (crc32(data.first(data.size()-4))!=expected_crc) throw std::runtime_error("Core checkpoint checksum mismatch");
    std::size_t pos=8;
    if (take(data,pos,4)!=1 || take(data,pos,4)!=GuestMemory::size || take(data,pos,4)!=page_size)
        throw std::runtime_error("Unsupported core checkpoint version or RAM layout");
    SaveIdentity id;
    id.core_abi_revision=std::uint32_t(take(data,pos,4));
    std::copy_n(data.begin()+pos,32,id.executable_sha256.begin()); pos+=32;
    std::copy_n(data.begin()+pos,32,id.assets_sha256.begin()); pos+=32;
    if (id!=expected) throw std::runtime_error("Core checkpoint belongs to different game data or core ABI");
    CoreCheckpoint state;
    state.manager=std::uint32_t(take(data,pos,4));
    state.logical_tick=take(data,pos,8);
    (void)state.memory.bytes(state.manager,state.manager ? 0x858 : 0);
    const auto count=take(data,pos,4);
    if (count>pages || data.size()!=pos+count*(page_size+4)+4)
        throw std::runtime_error("Invalid core checkpoint page count");
    std::uint32_t previous=0;
    for(std::uint32_t n=0;n<count;++n) {
        const auto page=std::uint32_t(take(data,pos,4));
        if (page>=pages || (n && page<=previous)) throw std::runtime_error("Unordered/duplicate core checkpoint page");
        if (!nonzero(data.subspan(pos,page_size))) throw std::runtime_error("Noncanonical zero checkpoint page");
        state.memory.write_bytes(page*page_size,data.subspan(pos,page_size));
        pos+=page_size; previous=page;
    }
    return state;
}

void write_checkpoint_atomic(const std::filesystem::path& destination,
                             const CoreCheckpoint& state,const SaveIdentity& id) {
    const auto data=encode_checkpoint(state,id);
    replace_save_file_atomic(destination,data,false);
}

void replace_save_file_atomic(const std::filesystem::path& destination,std::span<const std::uint8_t> data,
                             bool independent_temporary) {
    if(data.empty() || data.size()>128u*1024u*1024u) throw std::invalid_argument("Invalid save payload");
    // This is a core-managed slot path. CREATE_NEW/O_EXCL never clobbers a stale
    // temporary or another writer. No scan or removal of unrelated files.
    auto temporary=destination;
    temporary += ".pending";
    if(independent_temporary) {
        static std::atomic<std::uint64_t> serial{};
#ifdef _WIN32
        const auto pid=GetCurrentProcessId();
#else
        const auto pid=getpid();
#endif
        temporary += "." + std::to_string(pid) + "." +
                     std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "." +
                     std::to_string(serial.fetch_add(1,std::memory_order_relaxed));
    }
#ifdef _WIN32
    HANDLE file=CreateFileW(temporary.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file==INVALID_HANDLE_VALUE) throw std::system_error(GetLastError(),std::system_category(),"Create checkpoint temporary");
    bool closed=false;
    try {
        DWORD written=0;
        if(!WriteFile(file,data.data(),DWORD(data.size()),&written,nullptr) || written!=data.size() || !FlushFileBuffers(file))
            throw std::system_error(GetLastError(),std::system_category(),"Write checkpoint temporary");
        const BOOL close_ok=CloseHandle(file); closed=true;
        if(!close_ok) throw std::system_error(GetLastError(),std::system_category(),"Close checkpoint temporary");
        if(!MoveFileExW(temporary.c_str(),destination.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))
            throw std::system_error(GetLastError(),std::system_category(),"Replace checkpoint slot");
    } catch(...) {
        if(!closed) CloseHandle(file);
        DeleteFileW(temporary.c_str());
        throw;
    }
#else
    const int fd=::open(temporary.c_str(),O_WRONLY|O_CREAT|O_EXCL,0600);
    if(fd<0) throw std::system_error(errno,std::generic_category(),"Create checkpoint temporary");
    bool closed=false;
    try {
        std::size_t done=0;
        while(done<data.size()) {
            const auto written=::write(fd,data.data()+done,data.size()-done);
            if(written<0 && errno==EINTR) continue;
            if(written<=0) throw std::system_error(errno,std::generic_category(),"Write checkpoint temporary");
            done+=std::size_t(written);
        }
        if(::fsync(fd)) throw std::system_error(errno,std::generic_category(),"Flush checkpoint temporary");
        const int close_result=::close(fd); closed=true;
        if(close_result) throw std::system_error(errno,std::generic_category(),"Close checkpoint temporary");
        std::filesystem::rename(temporary,destination);
    } catch(...) {
        if(!closed) ::close(fd);
        ::unlink(temporary.c_str());
        throw;
    }
#endif
}

CoreCheckpoint read_checkpoint(const std::filesystem::path& path,const SaveIdentity& id) {
    std::ifstream input(path,std::ios::binary|std::ios::ate);
    if(!input) throw std::runtime_error("Cannot open core checkpoint");
    const auto size=input.tellg();
    if(size<0 || std::uint64_t(size)>max_size) throw std::runtime_error("Core checkpoint exceeds size limit");
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    input.seekg(0);
    input.read(reinterpret_cast<char*>(data.data()),std::streamsize(data.size()));
    if(!input || input.peek()!=std::char_traits<char>::eof()) throw std::runtime_error("Core checkpoint changed or truncated while reading");
    return decode_checkpoint(data,id);
}
}
