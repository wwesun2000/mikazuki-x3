#include "../windows/source_codec.hpp"
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>
extern "C" {
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>
#include <libswresample/swresample.h>
}
namespace kx3::platform::windows {
namespace {
void check(int r,const char* action){if(r<0){char why[AV_ERROR_MAX_STRING_SIZE]{};av_strerror(r,why,sizeof why);throw std::runtime_error(std::string(action)+": "+why);}}
struct Decoder {
    std::span<const std::uint8_t> source;
    std::int64_t offset=0;
    AVIOContext* io=nullptr;
    AVFormatContext* format=nullptr;
    AVCodecContext* codec=nullptr;
    AVFrame* frame=nullptr;
    AVPacket* packet=nullptr;
    SwsContext* scale=nullptr;
    int stream=-1;
    bool drained=false;
    static int read(void* self,std::uint8_t* dst,int n){auto& d=*static_cast<Decoder*>(self);
        n=int(std::min<std::int64_t>(n,d.source.size()-d.offset));if(!n)return AVERROR_EOF;
        std::memcpy(dst,d.source.data()+d.offset,n);d.offset+=n;return n;}
    static std::int64_t seek(void* self,std::int64_t n,int whence){auto& d=*static_cast<Decoder*>(self);
        if(whence&AVSEEK_SIZE)return d.source.size();whence&=~AVSEEK_FORCE;
        const auto base=whence==SEEK_SET?0:whence==SEEK_CUR?d.offset:whence==SEEK_END?std::int64_t(d.source.size()):-1;
        if(base<0 || n < -base || n>std::int64_t(d.source.size())-base)return AVERROR(EINVAL);
        return d.offset=base+n;}
    void close(){
        if(scale)sws_freeContext(scale);scale=nullptr;
        av_packet_free(&packet);av_frame_free(&frame);avcodec_free_context(&codec);avformat_close_input(&format);
        if(io){av_freep(&io->buffer);avio_context_free(&io);}
    }
    Decoder(std::span<const std::uint8_t> bytes,const char* demux,AVMediaType type):source(bytes){try{
        auto* buffer=static_cast<unsigned char*>(av_malloc(32768));if(!buffer)throw std::bad_alloc();
        io=avio_alloc_context(buffer,32768,0,this,read,nullptr,seek);if(!io){av_free(buffer);throw std::bad_alloc();}
        format=avformat_alloc_context();if(!format)throw std::bad_alloc();format->pb=io;format->flags|=AVFMT_FLAG_CUSTOM_IO;
        const auto* input=av_find_input_format(demux);if(!input)throw std::runtime_error(std::string("Decoder lacks format ")+demux);
        check(avformat_open_input(&format,nullptr,input,nullptr),"Open original media");
        check(avformat_find_stream_info(format,nullptr),"Inspect original media");
        const AVCodec* decoder=nullptr;stream=av_find_best_stream(format,type,-1,-1,&decoder,0);check(stream,"Find original media stream");
        codec=avcodec_alloc_context3(decoder);if(!codec)throw std::bad_alloc();
        check(avcodec_parameters_to_context(codec,format->streams[stream]->codecpar),"Copy codec parameters");
        codec->thread_count=1;check(avcodec_open2(codec,decoder,nullptr),"Open original decoder");
        frame=av_frame_alloc();packet=av_packet_alloc();if(!frame||!packet)throw std::bad_alloc();
    }catch(...){close();throw;}}
    ~Decoder(){close();}
    bool next(){
        for(;;){
            int r=avcodec_receive_frame(codec,frame);if(r==0)return true;if(r==AVERROR_EOF)return false;
            if(r!=AVERROR(EAGAIN))check(r,"Decode original frame");
            if(drained)throw std::runtime_error("Decoder requested data after drain");
            while((r=av_read_frame(format,packet))>=0 && packet->stream_index!=stream)av_packet_unref(packet);
            if(r==AVERROR_EOF){check(avcodec_send_packet(codec,nullptr),"Drain original decoder");drained=true;}
            else {check(r,"Read original packet");const int sent=avcodec_send_packet(codec,packet);av_packet_unref(packet);check(sent,"Submit original packet");}
        }
    }
    std::shared_ptr<const RasterFrame> rgba(){
        const int w=frame->width,h=frame->height;
        if(w<=0||h<=0||w>4096||h>4096)throw std::runtime_error("Invalid decoded video dimensions");
        auto out=std::make_shared<RasterFrame>();out->width=w;out->height=h;out->rgba.resize(std::size_t(w)*h*4);
        scale=sws_getCachedContext(scale,w,h,AVPixelFormat(frame->format),w,h,AV_PIX_FMT_RGBA,SWS_BICUBIC,nullptr,nullptr,nullptr);
        if(!scale)throw std::runtime_error("Cannot convert original video pixels");
        std::uint8_t* dest[]={out->rgba.data(),nullptr,nullptr,nullptr};int strides[]={4*w,0,0,0};
        if(sws_scale(scale,frame->data,frame->linesize,0,h,dest,strides)!=h)throw std::runtime_error("Incomplete decoded video frame");return out;
    }
};
}
struct MovieReader::Impl {
    std::vector<std::uint8_t> encoded;
    bool ps;std::uint32_t width,height,count,next=0;
    std::unique_ptr<Decoder> decoder;
    std::shared_ptr<const RasterFrame> last;
    Impl(std::span<const std::uint8_t> b,bool p,std::uint32_t w,std::uint32_t h,std::uint32_t c):encoded(b.begin(),b.end()),ps(p),width(w),height(h),count(c){
        if(!count||!w||!h||w>4096||h>4096)throw std::runtime_error("Invalid original movie description");}
    void reset(){decoder=std::make_unique<Decoder>(encoded,ps?"mpeg":"mpegvideo",AVMEDIA_TYPE_VIDEO);next=0;last.reset();}
    std::shared_ptr<const RasterFrame> read(std::uint32_t number){
        if(number>=count)throw std::runtime_error("Movie frame outside original member");
        if(last && number+1==next)return last;
        if(!decoder || number<next)reset();
        while(next<=number){if(!decoder->next())throw std::runtime_error("Movie ended before its original frame count");
            if(decoder->frame->width!=int(width)||decoder->frame->height!=int(height))throw std::runtime_error("Original movie dimension mismatch");
            last=decoder->rgba();++next;}return last;
    }
};
MovieReader::MovieReader(const std::filesystem::path&,std::span<const std::uint8_t> bytes,bool ps,std::uint32_t w,std::uint32_t h,std::uint32_t count)
    :impl_(std::make_unique<Impl>(bytes,ps,w,h,count)){}
MovieReader::~MovieReader()=default;
void MovieReader::prime(bool){if(!impl_->decoder)(void)impl_->read(0);}
std::shared_ptr<const RasterFrame> MovieReader::read(std::uint32_t frame,bool,bool){return impl_->read(frame);}
std::shared_ptr<const RasterFrame> decode_original_ipu(const std::filesystem::path&,std::vector<std::uint8_t> input){
    const auto u32=[&](unsigned p){return std::uint32_t(input[p])|std::uint32_t(input[p+1])<<8|std::uint32_t(input[p+2])<<16|std::uint32_t(input[p+3])<<24;};
    const std::array<std::uint8_t,8> tail{0,0,1,0xb0,0,0,1,0xb1};
    if(input.size()<24||input.size()>32u*1024*1024||!std::equal(input.begin(),input.begin()+4,"ipum")||u32(4)!=input.size()-8||u32(12)!=1||!std::equal(tail.begin(),tail.end(),input.end()-8))
        throw std::runtime_error("Unsupported original IPU framing");
    const auto d=u32(8),w=d&65535,h=d>>16;
    if(!w||!h||w>4096||h>4096||w%16||h%16)throw std::runtime_error("Unsupported source IPU dimensions");
    for(std::size_t i=16;i+4<=input.size()-8;++i)if(input[i]==0&&input[i+1]==0&&input[i+2]==1&&(input[i+3]==0xb0||input[i+3]==0xb1))throw std::runtime_error("Ambiguous IPU terminator");
    input.resize(input.size()-4);const auto size=std::uint32_t(input.size()-8);for(unsigned i=0;i<4;++i)input[4+i]=std::uint8_t(size>>(i*8));
    Decoder decoder(input,"ipu",AVMEDIA_TYPE_VIDEO);if(!decoder.next())throw std::runtime_error("IPU contains no image");
    auto result=decoder.rgba();if(result->width!=w||result->height!=h||decoder.next())throw std::runtime_error("IPU is not one complete source image");return result;
}
MusicPcm decode_original_vorbis(const std::filesystem::path&,std::span<const std::uint8_t> input){
    if(input.size()<64||!std::equal(input.begin(),input.begin()+4,"OggS")||input[4])throw std::runtime_error("Invalid Ogg page");
    const auto offset=27u+input[26];
    if(offset+30>input.size()||input[offset]!=1||!std::equal(input.begin()+offset+1,input.begin()+offset+7,"vorbis"))throw std::runtime_error("Missing Vorbis identification packet");
    MusicPcm out;out.channels=input[offset+11];for(unsigned i=0;i<4;++i)out.rate|=std::uint32_t(input[offset+12+i])<<(i*8);
    if(!out.channels||out.channels>2||out.rate!=48000)throw std::runtime_error("Unsupported original BGM layout");
    Decoder decoder(input,"ogg",AVMEDIA_TYPE_AUDIO);SwrContext* swr=nullptr;
    try{AVChannelLayout layout;av_channel_layout_default(&layout,out.channels);
        int result=swr_alloc_set_opts2(&swr,&layout,AV_SAMPLE_FMT_S16,out.rate,&decoder.codec->ch_layout,decoder.codec->sample_fmt,decoder.codec->sample_rate,0,nullptr);
        av_channel_layout_uninit(&layout);check(result,"Configure BGM converter");check(swr_init(swr),"Initialize BGM converter");
        while(decoder.next()){
            const auto start=out.interleaved.size();int capacity=swr_get_out_samples(swr,decoder.frame->nb_samples);
            if(capacity<0||std::uint64_t(start)+std::uint64_t(capacity)*out.channels>64ull*1024*1024)throw std::runtime_error("BGM sample budget exceeded");
            out.interleaved.resize(start+capacity*out.channels);std::uint8_t* dest[]={reinterpret_cast<std::uint8_t*>(out.interleaved.data()+start)};
            int n=swr_convert(swr,dest,capacity,const_cast<const std::uint8_t**>(decoder.frame->extended_data),decoder.frame->nb_samples);check(n,"Convert BGM");out.interleaved.resize(start+n*out.channels);
        }
        if(out.interleaved.empty())throw std::runtime_error("Empty original BGM");swr_free(&swr);
    }catch(...){swr_free(&swr);throw;}return out;
}
}
