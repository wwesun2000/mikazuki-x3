#include "project_movie.hpp"
#include "raster_loader.hpp"
#include "../movie_stream_index.hpp"
#include "../original_media_catalog.hpp"
#include <algorithm>

namespace kx3::platform::windows {
std::shared_ptr<const RasterFrame> PreparedMovie::load(std::uint32_t member,std::uint32_t frame,bool playing,bool loop) const {
    auto image=clips.at(member)->read(frame,playing,loop && member+1==clips.size());
    if(playing && member+1<clips.size() && timing[member].frames-frame<=8)
        clips[member+1]->prime(loop && member+2==clips.size());
    return image;
}

std::shared_ptr<const PreparedMovie> prepare_original_movie(const std::filesystem::path& root,
        const std::string& name,std::uint32_t size) {
    const auto* source=find_original_media(name);
    const auto it=std::lower_bound(stream_movies.begin(),stream_movies.end(),name,
        [](const StreamMovie& row,const std::string& key){return std::string_view(row.name)<key;});
    if(!source || source->size!=size || it==stream_movies.end() || it->name!=name)
        throw std::runtime_error("Unbound original movie: "+name);
    if(!it->count || it->count>2 || std::uint64_t(it->start)+it->count>stream_members.size())
        throw std::runtime_error("Invalid original movie index");
    const auto encoded=read_disc_resource(root,source->path,source->sha,size);
    const std::span<const std::uint8_t> bytes(encoded);
    auto movie=std::make_shared<PreparedMovie>();movie->source_hash=source->sha;
    if(name.ends_with(".pss"))movie->audio=decode_pss_audio(bytes);
    for(unsigned i=0;i<it->count;++i){
        const auto& c=stream_members[it->start+i];
        if(c.offset>bytes.size() || c.bytes>bytes.size()-c.offset)
            throw std::runtime_error("Original movie member bounds mismatch");
        const auto member=bytes.subspan(c.offset,c.bytes);
        if(source_bytes_sha256(member)!=c.sha)throw std::runtime_error("Original movie member identity mismatch");
        movie->clips.push_back(std::make_shared<MovieReader>(root,member,name.ends_with(".pss"),c.width,c.height,c.frames));
        const auto frame_bytes=std::size_t(c.width)*c.height*4;
        // Queue, decoder's current/next RGBA buffers, and the output pipe.
        movie->decoder_reserve+=(movie_lookahead_frames(frame_bytes,c.frames)+2)*frame_bytes+(1u<<20);
        MovieClipTiming timing{c.frames,c.num,c.den};
        if(movie->audio){
            const auto& a=*movie->audio;
            if(it->count!=1 || a.channels!=2 || a.rate!=48000 || a.interleaved.empty())
                throw std::runtime_error("Unsupported source PSS audio layout");
            const auto offset=a.audio_offset90k;
            const auto samples=(std::uint64_t(offset<0?-offset:offset)*8+7)/15;
            if(offset<0)timing.video_start_sample=samples;
            else timing.audio_start_sample=samples;
            timing.audio_frames=a.interleaved.size()/2;
        }
        movie->timing.push_back(timing);
        movie->total_frames+=c.frames;
    }
    return movie;
}
}
