#include "source_codec.hpp"
#include "raster_loader.hpp"
#define NOMINMAX
#include <windows.h>
#include <array>
#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <mutex>
#include <sstream>
#include <thread>

namespace kx3::platform::windows {
namespace {
struct Handle {
    HANDLE value=nullptr;
    ~Handle(){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);}
    Handle(const Handle&)=delete;
    explicit Handle(HANDLE h=nullptr):value(h){}
    Handle(Handle&& other) noexcept:value(other.value){other.value=nullptr;}
    Handle& operator=(Handle&& other) noexcept {
        if(this!=&other){if(value && value!=INVALID_HANDLE_VALUE)CloseHandle(value);value=other.value;other.value=nullptr;}
        return *this;
    }
};
struct Scratch {
    std::filesystem::path dir,source,decoded,log;
    explicit Scratch(const std::filesystem::path& project,bool audio=false) {
        static std::atomic<unsigned> serial{};
        auto base=project/"local/port-assets/decode-temp";
        std::filesystem::create_directories(base);
        for(unsigned tries=0;tries<100;++tries){
            dir=base/(std::to_string(GetCurrentProcessId())+"-"+std::to_string(GetTickCount64())+"-"+std::to_string(++serial));
            if(std::filesystem::create_directory(dir)){
                source=dir/(audio?"source.ogg":"source.ipu");decoded=dir/(audio?"sound.pcm":"frame.rgba");log=dir/"ffmpeg.log";return;
            }
        }
        throw std::runtime_error("Cannot reserve original image decoder working directory");
    }
    ~Scratch(){
        std::error_code ec;
        for(const auto* p:{&source,&decoded,&log,&dir})std::filesystem::remove(*p,ec);
    }
};
std::wstring quote(const std::filesystem::path& p) {
    const auto name=std::filesystem::absolute(p).wstring();
    if(name.find(L'"')!=std::wstring::npos)throw std::invalid_argument("Invalid file path");
    return L"\""+name+L"\"";
}
void verify_decoder(Handle& binary) {
    LARGE_INTEGER size{};
    if(binary.value==INVALID_HANDLE_VALUE || !GetFileSizeEx(binary.value,&size) || size.QuadPart!=87638016)
        throw std::runtime_error("Original-media FFmpeg binary unavailable or wrong size");
    // Keep the verified file open without write/delete sharing. A new path or
    // directory alias can reuse verification only if it opens that same file.
    static std::mutex lock;
    static Handle pinned;
    static BY_HANDLE_FILE_INFORMATION verified{};
    std::lock_guard guard(lock);
    BY_HANDLE_FILE_INFORMATION current{};
    const bool identified=GetFileInformationByHandle(binary.value,&current) &&
        (current.nFileIndexLow || current.nFileIndexHigh);
    if(identified && pinned.value && current.dwVolumeSerialNumber==verified.dwVolumeSerialNumber &&
       current.nFileIndexHigh==verified.nFileIndexHigh && current.nFileIndexLow==verified.nFileIndexLow)return;
    Handle mapping(CreateFileMappingW(binary.value,nullptr,PAGE_READONLY,0,0,nullptr));
    struct View {const std::uint8_t* data;~View(){if(data)UnmapViewOfFile(data);}};
    View view{static_cast<const std::uint8_t*>(MapViewOfFile(mapping.value,FILE_MAP_READ,0,0,0))};
    if(!view.data || source_bytes_sha256({view.data,std::size_t(size.QuadPart)})!=
        "2ce797a0f88d7f067180338fb227f7b1928ea727bd9a4d7a1d022f7c52af71a3")
        throw std::runtime_error("Original-media FFmpeg identity mismatch");
    if(identified){
        HANDLE copy=nullptr;
        if(DuplicateHandle(GetCurrentProcess(),binary.value,GetCurrentProcess(),&copy,0,FALSE,DUPLICATE_SAME_ACCESS)){
            pinned=Handle(copy);verified=current;
        }
    }
}
Handle start_decoder(const std::filesystem::path& root,const Scratch& files,const std::wstring& format,
                     HANDLE stream=nullptr) {
    const auto exe=std::filesystem::absolute(root/"local/dependencies/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe");
    Handle binary(CreateFileW(exe.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,0,nullptr));
    verify_decoder(binary);
    SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
    Handle log(CreateFileW(files.log.c_str(),GENERIC_WRITE,FILE_SHARE_READ,&inherit,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr));
    Handle input(CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&inherit,OPEN_EXISTING,0,nullptr));
    if(input.value==INVALID_HANDLE_VALUE || log.value==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot open codec log or input");
    STARTUPINFOEXW start{};start.StartupInfo.cb=sizeof(start);start.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
    start.StartupInfo.hStdInput=input.value;start.StartupInfo.hStdOutput=stream?stream:log.value;start.StartupInfo.hStdError=log.value;
    SIZE_T n=0;InitializeProcThreadAttributeList(nullptr,1,0,&n);
    std::vector<std::uint8_t> storage(n);
    start.lpAttributeList=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
    if(!InitializeProcThreadAttributeList(start.lpAttributeList,1,0,&n))throw std::runtime_error("Cannot initialize codec launch attributes");
    struct Attributes {LPPROC_THREAD_ATTRIBUTE_LIST list;~Attributes(){DeleteProcThreadAttributeList(list);}} attributes{start.lpAttributeList};
    HANDLE allowed[]{input.value,log.value,stream};
    if(!UpdateProcThreadAttribute(start.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,allowed,(stream?3:2)*sizeof(HANDLE),nullptr,nullptr))
        throw std::runtime_error("Cannot restrict inherited codec handles");
    auto command=quote(exe)+L" -hide_banner -nostdin -v error -n -xerror -err_detect explode -threads 2 -filter_threads 1 -i "+
        quote(files.source)+format+(stream?L"pipe:1":quote(files.decoded));
    PROCESS_INFORMATION process{};
    if(!CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|EXTENDED_STARTUPINFO_PRESENT,
                       nullptr,nullptr,&start.StartupInfo,&process))throw std::runtime_error("Cannot launch original image decoder");
    Handle thread(process.hThread);
    return Handle(process.hProcess);
}
void run_decoder(const std::filesystem::path& root,const Scratch& files,bool audio=false) {
    const auto format=audio ? L" -map 0:a:0 -vn -sn -dn -c:a pcm_s16le -f s16le " :
                              L" -map 0:v:0 -an -sn -dn -pix_fmt rgba -f rawvideo ";
    auto child=start_decoder(root,files,format);
    if(WaitForSingleObject(child.value,30000)!=WAIT_OBJECT_0){
        TerminateProcess(child.value,2);WaitForSingleObject(child.value,INFINITE);
        throw std::runtime_error("Original image decode timed out");
    }
    DWORD status=0;
    if(!GetExitCodeProcess(child.value,&status) || status || std::filesystem::file_size(files.log)!=0){
        std::ifstream diagnostic(files.log);std::string line;std::getline(diagnostic,line);
        throw std::runtime_error("Strict original image decode failed: "+line.substr(0,240));
    }
}
}

struct MovieReader::Impl {
    std::filesystem::path root;
    Scratch files;
    std::uint32_t width,height,count,next=0;
    Handle child,pipe,read_event;
    std::shared_ptr<RasterFrame> last;
    Impl(const std::filesystem::path& project,std::span<const std::uint8_t> data,bool ps,
         std::uint32_t w,std::uint32_t h,std::uint32_t frames)
        :root(project),files(project),width(w),height(h),count(frames) {
        if(!w || !h || w>1920 || h>1080 || !frames || frames>36000 || data.empty())
            throw std::runtime_error("Unsupported source movie geometry or duration");
        files.source=files.dir/(ps?"source.pss":"source.m2v");
        std::ofstream out(files.source,std::ios::binary);
        out.exceptions(std::ios::failbit|std::ios::badbit);
        out.write(reinterpret_cast<const char*>(data.data()),data.size());out.close();
    }
    void stop() noexcept {
        pipe=Handle();
        if(child.value && WaitForSingleObject(child.value,100)==WAIT_TIMEOUT) {
            TerminateProcess(child.value,2);WaitForSingleObject(child.value,5000);
        }
        child=Handle();next=0;
    }
    ~Impl(){
        {std::lock_guard lock(mutex);closing=true;}
        changed.notify_all();
        if(worker.joinable())worker.join();
        stop();
    }
    void restart(){
        stop();
        static std::atomic<unsigned> serial{};
        const auto name=std::wstring(L"\\\\.\\pipe\\kx3-movie-")+std::to_wstring(GetCurrentProcessId())+
                        L"-"+std::to_wstring(++serial);
        pipe=Handle(CreateNamedPipeW(name.c_str(),PIPE_ACCESS_INBOUND|FILE_FLAG_OVERLAPPED|FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE|PIPE_READMODE_BYTE|PIPE_WAIT|PIPE_REJECT_REMOTE_CLIENTS,1,0,1<<20,0,nullptr));
        if(pipe.value==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot create the movie decode pipe");
        SECURITY_ATTRIBUTES sa{sizeof(sa),nullptr,TRUE};
        Handle writer(CreateFileW(name.c_str(),GENERIC_WRITE,0,&sa,OPEN_EXISTING,0,nullptr));
        if(writer.value==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot open the movie decode pipe");
        if(!read_event.value)read_event=Handle(CreateEventW(nullptr,TRUE,FALSE,nullptr));
        if(!read_event.value)throw std::runtime_error("Cannot create the movie read event");
        child=start_decoder(root,files,L" -map 0:v:0 -an -sn -dn -fps_mode passthrough -pix_fmt rgba -f rawvideo ",writer.value);
        last.reset();
    }
    void read_bytes(std::span<std::uint8_t> output) {
        const auto deadline=GetTickCount64()+30000;
        while(!output.empty()){
            OVERLAPPED operation{};operation.hEvent=read_event.value;
            ResetEvent(read_event.value);
            DWORD got=0;
            if(!ReadFile(pipe.value,output.data(),static_cast<DWORD>(output.size()),&got,&operation)){
                if(GetLastError()!=ERROR_IO_PENDING)throw std::runtime_error("MPEG decoder stopped before its source frame count");
                const auto now=GetTickCount64();
                if(WaitForSingleObject(read_event.value,now<deadline?DWORD(deadline-now):0)!=WAIT_OBJECT_0){
                    CancelIoEx(pipe.value,&operation);
                    GetOverlappedResult(pipe.value,&operation,&got,TRUE);
                    throw std::runtime_error("MPEG frame decode timed out");
                }
                if(!GetOverlappedResult(pipe.value,&operation,&got,FALSE))throw std::runtime_error("Cannot read MPEG pixels");
            }
            if(!got)throw std::runtime_error("Empty MPEG decoder read");
            output=output.subspan(got);
        }
    }
    std::shared_ptr<const RasterFrame> decode(std::uint32_t index){
        if(index>=count)throw std::out_of_range("Source movie frame out of bounds");
        if(last && index+1==next)return last;
        if(!child.value || index<next)restart();
        try{
            auto image=std::make_shared<RasterFrame>();image->width=width;image->height=height;
            image->rgba.resize(std::size_t(width)*height*4);
            while(next<=index){read_bytes(image->rgba);++next;}
            if(next==count){
                DWORD status=0,extra=0;
                // A process that emitted extra output can fill its pipe before exiting.
                const auto until=GetTickCount64()+30000;
                while(WaitForSingleObject(child.value,1)==WAIT_TIMEOUT){
                    if((PeekNamedPipe(pipe.value,nullptr,0,nullptr,&extra,nullptr) && extra) || GetTickCount64()>=until)
                        throw std::runtime_error("MPEG decoder exceeded its indexed frame count");
                }
                if((PeekNamedPipe(pipe.value,nullptr,0,nullptr,&extra,nullptr) && extra) ||
                   !GetExitCodeProcess(child.value,&status) || status || std::filesystem::file_size(files.log))
                    throw std::runtime_error("MPEG decoder did not terminate cleanly at its source frame count");
            }
            last=std::move(image);return last;
        }catch(...){stop();last.reset();throw;}
    }
    // Only the decoder worker touches the pipe after playback starts. Guest
    // timing and checkpoint state remain on the game thread. Prefetch alone
    // reads one poster frame synchronously and does not start a worker.
    struct Picture {
        std::uint32_t index;
        std::shared_ptr<const RasterFrame> image;
        std::exception_ptr error;
    };
    std::mutex mutex;
    std::condition_variable changed;
    std::thread worker;
    std::deque<Picture> ready;
    std::uint32_t requested=0, producer=0;
    std::uint64_t epoch=0;
    bool closing=false,repeat=false;
    void prime(bool loop){
        if(worker.joinable())return;
        std::lock_guard lock(mutex);
        requested=producer=0;repeat=loop;
        worker=std::thread(&Impl::fill_queue,this);
    }
    void fill_queue(){
        const auto capacity=movie_lookahead_frames(std::size_t(width)*height*4,count);
        std::unique_lock lock(mutex);
        while(true){
            changed.wait(lock,[&]{return closing || (producer<count && ready.size()<capacity);});
            if(closing)return;
            const auto ticket=epoch;
            Picture picture{producer};
            lock.unlock();
            try{picture.image=decode(picture.index);}
            catch(...){picture.error=std::current_exception();}
            lock.lock();
            if(ticket!=epoch)continue;
            producer=picture.error?count:picture.index+1;
            if(!picture.error && producer==count && repeat)producer=0;
            ready.push_back(std::move(picture));
            changed.notify_all();
        }
    }
    std::shared_ptr<const RasterFrame> read(std::uint32_t index,bool playing,bool loop){
        if(index>=count)throw std::out_of_range("Source movie frame out of bounds");
        if(!playing && !worker.joinable())return decode(index);
        std::unique_lock lock(mutex);
        if(!worker.joinable() || index!=requested || repeat!=loop){
            ++epoch;ready.clear();producer=index;repeat=loop;
        }
        if(!worker.joinable())worker=std::thread(&Impl::fill_queue,this);
        changed.notify_all();
        changed.wait(lock,[&]{return !ready.empty();});
        auto picture=std::move(ready.front());ready.pop_front();
        requested=index+1;
        if(requested==count && repeat)requested=0;
        changed.notify_all();
        if(picture.index!=index)throw std::logic_error("Source movie lookahead index mismatch");
        if(picture.error){
            requested=count; // Retry at the exact failed picture.
            std::rethrow_exception(picture.error);
        }
        return std::move(picture.image);
    }
};
MovieReader::MovieReader(const std::filesystem::path& root,std::span<const std::uint8_t> bytes,bool ps,
                         std::uint32_t width,std::uint32_t height,std::uint32_t count)
    :impl_(std::make_unique<Impl>(root,bytes,ps,width,height,count)){}
MovieReader::~MovieReader()=default;
void MovieReader::prime(bool loop){impl_->prime(loop);}
std::shared_ptr<const RasterFrame> MovieReader::read(std::uint32_t frame,bool playing,bool loop){
    return impl_->read(frame,playing,loop);
}

std::shared_ptr<const RasterFrame> decode_original_ipu(const std::filesystem::path& root,std::vector<std::uint8_t> input) {
    const auto u32=[&](unsigned pos){return std::uint32_t(input[pos])|std::uint32_t(input[pos+1])<<8|
        std::uint32_t(input[pos+2])<<16|std::uint32_t(input[pos+3])<<24;};
    const std::array<std::uint8_t,8> tail{0,0,1,0xb0,0,0,1,0xb1};
    if(input.size()<24 || input.size()>32u*1024*1024 || !std::equal(input.begin(),input.begin()+4,"ipum") ||
       u32(4)!=input.size()-8 || u32(12)!=1 || !std::equal(tail.begin(),tail.end(),input.end()-8))
        throw std::runtime_error("Unsupported original IPU framing");
    const auto dimensions=u32(8), width=dimensions&65535, height=dimensions>>16;
    if(!width || !height || width>4096 || height>4096 || (width%16) || (height%16))
        throw std::runtime_error("Unsupported source IPU dimensions");
    for(std::size_t i=16;i+4<=input.size()-8;++i)
        if(input[i]==0 && input[i+1]==0 && input[i+2]==1 && (input[i+3]==0xb0 || input[i+3]==0xb1))
            throw std::runtime_error("Ambiguous original IPU frame terminator");
    input.resize(input.size()-4);
    const auto length=std::uint32_t(input.size()-8);
    for(unsigned i=0;i<4;++i)input[4+i]=std::uint8_t(length>>(8*i));
    Scratch files(root);
    {
        std::ofstream original(files.source,std::ios::binary);
        original.exceptions(std::ios::failbit|std::ios::badbit);
        original.write(reinterpret_cast<const char*>(input.data()),input.size());original.close();
    }
    run_decoder(root,files);
    const auto pixels=std::size_t(width)*height*4;
    if(std::filesystem::file_size(files.decoded)!=pixels)throw std::runtime_error("Decoded IPU is not exactly one full source frame");
    auto out=std::make_shared<RasterFrame>();out->width=width;out->height=height;out->rgba.resize(pixels);
    std::ifstream rgb(files.decoded,std::ios::binary);
    if(!rgb.read(reinterpret_cast<char*>(out->rgba.data()),pixels))throw std::runtime_error("Truncated decoded IPU");
    return out;
}

MusicPcm decode_original_vorbis(const std::filesystem::path& root,std::span<const std::uint8_t> input) {
    if(input.size()<64 || !std::equal(input.begin(),input.begin()+4,"OggS") || input[4]!=0)
        throw std::runtime_error("Invalid original Ogg page");
    const auto offset=27u+input[26];
    if(offset+30>input.size() || input[offset]!=1 || !std::equal(input.begin()+offset+1,input.begin()+offset+7,"vorbis"))
        throw std::runtime_error("Original Ogg identification packet missing");
    MusicPcm result;
    result.channels=input[offset+11];
    for(unsigned i=0;i<4;++i)result.rate|=std::uint32_t(input[offset+12+i])<<(8*i);
    if(!result.channels || result.channels>2 || result.rate!=48000)
        throw std::runtime_error("Unsupported original BGM channel layout or rate");
    Scratch files(root,true);
    {
        std::ofstream original(files.source,std::ios::binary);
        original.exceptions(std::ios::failbit|std::ios::badbit);
        original.write(reinterpret_cast<const char*>(input.data()),input.size());original.close();
    }
    run_decoder(root,files,true);
    const auto bytes=std::filesystem::file_size(files.decoded);
    if(!bytes || bytes>128u*1024*1024 || bytes%(2*result.channels))throw std::runtime_error("Invalid decoded BGM samples");
    result.interleaved.resize(bytes/2);
    std::ifstream pcm(files.decoded,std::ios::binary);
    if(!pcm.read(reinterpret_cast<char*>(result.interleaved.data()),bytes))throw std::runtime_error("Truncated decoded BGM");
    return result;
}
}
