#include "project_media.hpp"
#include "../../core/guest_memory.hpp"
#include "../../core/sab_animation.hpp"
#include "../sab_layer.hpp"
#include "raster_loader.hpp"
#include "source_codec.hpp"
#include "../original_media_catalog.hpp"
#include "../panel_members.hpp"
#include <algorithm>
#include <charconv>
#include <set>

namespace kx3::platform::windows {
std::vector<std::uint8_t> ProjectImageServices::read_panel_member(const std::string& path) const {
    for(const auto& member:panel_members)if(path==member.path)
        return read_disc_resource(root_,member.path,member.sha,member.size);
    throw std::runtime_error("Unknown original panel resource "+path);
}
std::uint32_t ProjectImageServices::source_file_size(const std::string& name) const {
    if(const auto* original=find_original_media(name)) {
        if(disc_resource_size(root_,original->path)!=original->size)
            throw std::runtime_error("ISO member size differs from the source binding: "+name);
        return original->size;
    }
    // The catalog includes every DISC.FAD movie of these four types. The
    // original 145958 returns zero on ENOENT; 137B98 then uses the disc's
    // fallback image. Other virtual namespaces require their own bindings.
    if(name.starts_with("MOVIE/") && name.find_first_of("/\\",6)==std::string::npos &&
       (name.ends_with(".ipu") || name.ends_with(".m2v") || name.ends_with(".mmv") || name.ends_with(".pss")))
        return 0;
    throw std::runtime_error("No verified source file mapping for "+name);
}
std::span<const std::uint8_t> ProjectImageServices::verified_bank() const {
    if (bank_.empty()) bank_=read_disc_resource(root_,"SOUND/SSDVDAT/se.dat",
        "e481a5823ee83d6f67e16b4aabbc93807f2790eb8ec17c34b609aa658285c51c",50339840);
    return bank_;
}
bool ProjectImageServices::sound_retention_flag(std::uint32_t id) const {
    if (id<1000) return false;
    const auto record=find_bank_sound(verified_bank(),id);
    return record && (record->flags&0x30)==0x10; // 1D3858 excludes bit 5, 1D2EE4 reads bit 4.
}
std::shared_ptr<const PreparedSound> ProjectImageServices::prepared_sound(std::uint32_t id) const noexcept {
    for(auto generation=prepared_.rbegin();generation!=prepared_.rend();++generation) {
        const auto sound=generation->second.sounds.find(id);
        if(sound!=generation->second.sounds.end())return sound->second;
    }
    return {};
}
std::shared_ptr<const PreparedSound> ProjectImageServices::open_bank_sound(std::uint32_t id) const {
    if(auto stored=prepared_sound(id))return stored;
    auto bank=verified_bank();
    const auto record=find_bank_sound(bank,id);
    if(!record)throw std::runtime_error("SE ID absent from original bank: "+std::to_string(id));
    auto sound=std::make_shared<PreparedSound>();
    sound->record=*record;
    sound->source_hash=source_bytes_sha256(bank.subspan(record->offset,record->allocation));
    for(unsigned i=0;i<record->channels;++i){
        sound->channels.push_back(decode_bank_channel(bank,*record,i));
        sound->samples+=sound->channels.back().samples.size();
    }
    return sound;
}
std::shared_ptr<const PreparedSound> ProjectImageServices::sound_for_play(std::uint32_t id) const {
    if (auto sound=prepared_sound(id)) return sound;
    if (id<1 || id>7) return {};
    if(auto it=menu_sounds_.find(id);it!=menu_sounds_.end())return it->second;
    auto sound=open_bank_sound(id);menu_sounds_.emplace(id,sound);
    return sound;
}
std::span<const std::uint8_t> ProjectImageServices::sab_file(std::uint64_t generation,const std::string& name) const {
    return prepared_.at(generation).animations.at(name);
}
MediaPrepareReceipt ProjectImageServices::preload(const SourceResourcePlan& plan) {
    if(prepared_.size()>=max_prepared_scenes)throw std::runtime_error("Prepared scene surfaces exceed the host media budget");
    PreparedImages prepared;prepared.plan=plan;
    MediaPrepareReceipt receipt;
    // Every generation can become a composited display surface. Separately
    // charge each resident decoded allocation once, including a movie's queue.
    std::uint64_t bytes=scene_surface_reserve*(prepared_.size()+1);
    constexpr auto byte_limit=prepared_media_budget;
    std::set<const void*> counted;
    auto charge=[&](const void* owner,std::uint64_t size){
        if(!counted.insert(owner).second)return;
        if(size>byte_limit-bytes)
            throw std::runtime_error("Scene "+plan.primary_virtual_name+" exceeds the prepared media budget ("+
                                     std::to_string(bytes)+" resident + "+std::to_string(size)+" bytes)");
        bytes+=size;
    };
    for(const auto& [generation,state]:prepared_) {
        for(const auto& [name,frame]:state.frames)charge(frame.get(),frame->rgba.size());
        for(const auto& [name,data]:state.animations)charge(data.data(),data.size());
        for(const auto& [id,sound]:state.sounds)charge(sound.get(),sound->samples*2);
        for(const auto& [name,music]:state.music)charge(music.get(),music->pcm.interleaved.size()*2);
        if(state.movie)charge(state.movie.get(),state.movie->decoder_reserve+
                              (state.movie->audio?state.movie->audio->interleaved.size()*2:0));
    }
    auto prepare_sound=[&](std::uint32_t id) -> const PreparedSound& {
        if(auto it=prepared.sounds.find(id);it!=prepared.sounds.end())return *it->second;
        for(const auto& [generation,state]:prepared_) {
            if(auto it=state.sounds.find(id);it!=state.sounds.end()) {
                prepared.sounds.emplace(id,it->second);return *it->second;
            }
        }
        auto bank=verified_bank();
        const auto record=find_bank_sound(bank,id);
        if(!record)throw std::runtime_error("SE ID absent from original bank: "+std::to_string(id));
        const auto required=std::uint64_t(record->stream_bytes/16)*28*2*record->channels;
        if(required>byte_limit-bytes)throw std::runtime_error("SE "+std::to_string(id)+" exceeds prepared media budget");
        auto sound=open_bank_sound(id);
        charge(sound.get(),sound->samples*2);
        prepared.sounds.emplace(id,sound);
        return *sound;
    };
    for(const auto& asset:plan.assets) {
        if(asset.source_audio_class==2) {
            const auto same=prepared.music.find(asset.resolved_name);
            auto track=same==prepared.music.end()?open_music(asset.virtual_name):same->second;
            const auto decoded=track->pcm.interleaved.size()*2;
            charge(track.get(),decoded);
            MediaAssetReceipt done;
            done.virtual_name=asset.virtual_name;done.source_sha256=track->source_hash;
            done.source_size_bytes=asset.source_size_bytes;done.decoded_kind=MediaDecodedKind::Audio;
            done.sample_count=track->pcm.interleaved.size()/track->pcm.channels;done.decoded_bytes=decoded;
            receipt.assets.push_back(std::move(done));prepared.music.emplace(asset.resolved_name,track);
            continue;
        }
        if(asset.source_audio_class==1) {
            std::uint32_t id=0;
            const char* first=asset.resolved_name.data();
            const char* end=first+asset.resolved_name.size();
            const auto parsed=std::from_chars(first,end,id);
            if(parsed.ec!=std::errc{} || parsed.ptr!=end)throw std::runtime_error("Invalid original SE identifier");
            const auto& sound=prepare_sound(id);
            MediaAssetReceipt done;
            done.virtual_name=asset.virtual_name;done.source_sha256=sound.source_hash;
            done.source_size_bytes=asset.source_size_bytes;done.decoded_kind=MediaDecodedKind::Audio;
            done.sample_count=sound.samples;done.decoded_bytes=2*sound.samples;
            receipt.assets.push_back(std::move(done));
            continue;
        }
        if(asset.source_type==10 && asset.required_kind==MediaDecodedKind::Data) {
            const auto* original=find_original_media(asset.virtual_name);
            if(!original || original->size!=asset.source_size_bytes)throw std::runtime_error("Unbound original SAB file");
            auto src=read_disc_resource(root_,original->path,original->sha,original->size);
            const auto info=inspect_sab_file(src);
            MediaAssetReceipt done;
            done.virtual_name=asset.virtual_name;done.source_sha256=original->sha;done.source_size_bytes=original->size;
            done.decoded_kind=MediaDecodedKind::Data;done.frame_count=info.frames;
            for(std::uint32_t frame=0;frame<info.frames;++frame){
                const auto l=inspect_sab_layer(src,info,frame);
                done.decoded_bytes+=std::uint64_t(l.color_width)*l.color_height+std::uint64_t(l.mask_width)*l.mask_height/2;
            }
            charge(src.data(),src.size());
            prepared.animations.emplace(asset.virtual_name,std::move(src));receipt.assets.push_back(std::move(done));continue;
        }
        if(asset.required_kind==MediaDecodedKind::Video) {
            if(!asset.primary || prepared.movie)throw std::runtime_error("Multiple movie tracks need their original compositor");
            const auto* original=find_original_media(asset.virtual_name);
            if(!original || original->size!=asset.source_size_bytes)throw std::runtime_error("Unbound original movie size");
            std::shared_ptr<const PreparedMovie> movie;
            std::shared_ptr<const RasterFrame> first;
            for(const auto& [id,state]:prepared_){
                if(state.movie && state.plan.primary_virtual_name==asset.virtual_name){
                    movie=state.movie;first=state.frames.at(asset.virtual_name);break;
                }
            }
            if(!movie){
                movie=prepare_original_movie(root_,asset.virtual_name,asset.source_size_bytes);
                first=movie->load(0,0);
            }
            MediaAssetReceipt done;
            done.virtual_name=asset.virtual_name;done.source_sha256=movie->source_hash;
            done.source_size_bytes=asset.source_size_bytes;done.decoded_kind=MediaDecodedKind::Video;
            done.width=first->width;done.height=first->height;done.frame_count=movie->total_frames;
            done.decoded_bytes=first->rgba.size(); // Later pictures are decoded at their presentation time.
            if(movie->audio)done.decoded_bytes+=movie->audio->interleaved.size()*2;
            charge(first.get(),first->rgba.size());
            charge(movie.get(),movie->decoder_reserve+(movie->audio?movie->audio->interleaved.size()*2:0));
            prepared.frames.emplace(asset.virtual_name,std::move(first));prepared.movie=std::move(movie);
            receipt.assets.push_back(std::move(done));continue;
        }
        if(asset.required_kind!=MediaDecodedKind::Image)
            throw std::runtime_error("Requested asset needs an actual video/audio/data decoder");
        const auto* original=find_original_media(asset.virtual_name);
        if(!original || asset.source_size_bytes!=original->size)
            throw std::runtime_error("Requested image differs from its original FAD entry");
        const auto source=read_disc_resource(root_,original->path,original->sha,original->size);
        std::shared_ptr<const RasterFrame> frame;
        if(auto same=prepared.frames.find(asset.virtual_name);same!=prepared.frames.end())frame=same->second;
        for(auto it=prepared_.rbegin();!frame && it!=prepared_.rend();++it){
            auto same=it->second.frames.find(asset.virtual_name);
            if(same!=it->second.frames.end())frame=same->second;
        }
        if(!frame)frame=decode_original_ipu(root_,source);
        charge(frame.get(),frame->rgba.size());
        prepared.frames.emplace(asset.virtual_name,frame);
        MediaAssetReceipt done;
        done.virtual_name=asset.virtual_name;done.source_sha256=original->sha;
        done.source_size_bytes=original->size;done.decoded_kind=MediaDecodedKind::Image;
        done.decoded_bytes=frame->rgba.size();done.width=frame->width;done.height=frame->height;done.frame_count=1;
        receipt.assets.push_back(std::move(done));
    }
    for(const auto id:plan.audio.retain_ids) { (void)prepare_sound(id);receipt.retained_sound_ids.push_back(id); }
    for(const auto& name:plan.audio.prepare_bgm) {
        if(!prepared.music.contains(name))throw std::runtime_error("Original BGM request has no prepared PCM");
        receipt.prepared_bgm.push_back(name);
    }
    receipt.prepared_generation=next_generation_;
    receipt.current_presentation_unchanged=true;
    validate_media_receipt(plan,receipt);
    prepared_.emplace(next_generation_,std::move(prepared));
    ++next_generation_;
    return receipt;
}
std::shared_ptr<const PreparedImages::Music> ProjectImageServices::prepared_music(const std::string& name) const {
    for(auto it=prepared_.rbegin();it!=prepared_.rend();++it) {
        if(auto track=it->second.music.find(name);track!=it->second.music.end())return track->second;
    }
    return {};
}
std::shared_ptr<const PreparedImages::Music> ProjectImageServices::open_music(const std::string& name) const {
    if(auto live=prepared_music(name))return live;
    const auto* file=find_original_media(name);
    if(!file || !name.ends_with(".ogg"))throw std::runtime_error("Unbound original Vorbis name: "+name);
    const auto encoded=read_disc_resource(root_,file->path,file->sha,file->size);
    const auto bank=read_disc_resource(root_,"SOUND/SSDVDAT/bgm.dat",
        "ec59764f45c520bcd439ae13b21e642a4d66dc84e4d70fb1375d79903404892b",57344);
    const auto stem=name.substr(0,name.size()-4);
    for(unsigned i=0;i<1000;++i){
        const auto* r=bank.data()+56*i;
        if(!(r[0]&0x80))break;
        const auto* end=std::find(r+40,r+54,0);
        if(std::string(r+40,end)!=stem)continue;
        if(!(r[3]&0x20))throw std::runtime_error("Original music record is not Vorbis");
        auto track=std::make_shared<PreparedImages::Music>();
        track->pcm=decode_original_vorbis(root_,encoded);
        auto le=[&](unsigned offset){return std::uint32_t(r[offset])|std::uint32_t(r[offset+1])<<8|
            std::uint32_t(r[offset+2])<<16|std::uint32_t(r[offset+3])<<24;};
        track->name=name;track->source_hash=file->sha;track->volume=r[38]|unsigned(r[39])<<8;
        track->loop_start=le(4);track->loop_end=le(8);track->loop=(r[3]&0x10)!=0;
        const auto frames=track->pcm.interleaved.size()/track->pcm.channels;
        if(track->loop && (track->loop_start>=track->loop_end || track->loop_end>frames))
            throw std::runtime_error("Original BGM loop outside decoded PCM");
        return track;
    }
    throw std::runtime_error("Missing original BGM metadata: "+name);
}
void ProjectImageServices::discard_prepared(std::uint64_t generation) noexcept {
    if(generation && generation==current_generation_)release_after_display_=true;
    else prepared_.erase(generation);
}
void ProjectImageServices::rollback_prepared(std::uint64_t id) noexcept {
    if(id!=current_generation_ && prepared_.erase(id) && id+1==next_generation_)next_generation_=id;
}
void ProjectImageServices::restore_prepared(std::uint64_t id,const SourceResourcePlan& plan) {
    if(id<next_generation_ || id==UINT64_MAX)throw std::runtime_error("Invalid saved scene generation");
    next_generation_=id;
    if(preload(plan).prepared_generation!=id)throw std::runtime_error("Could not reconstruct saved scene");
}
void ProjectImageServices::restore_display(std::uint64_t visible,std::uint64_t next,bool release_after_display,
        std::uint32_t member,std::uint32_t frame) {
    if(next<next_generation_ || next==UINT64_MAX || (visible && !has_decoded_primary(visible)) ||
       (!visible && release_after_display))throw std::runtime_error("Invalid visible scene in save");
    if(visible && !movie_timings(visible).empty())stage_movie_frame(visible,member,frame,false);
    else if(member || frame)throw std::runtime_error("Still image has a movie frame position");
    if(visible)commit_image(visible);
    next_generation_=next;
    release_after_display_=release_after_display;
}
bool ProjectImageServices::has_decoded_primary(std::uint64_t generation) const noexcept {
    const auto row=prepared_.find(generation);
    return row!=prepared_.end() && row->second.frames.contains(row->second.plan.primary_virtual_name);
}
std::span<const MovieClipTiming> ProjectImageServices::movie_timings(std::uint64_t generation) const noexcept {
    const auto it=prepared_.find(generation);
    if(it==prepared_.end() || !it->second.movie)return {};
    return it->second.movie->timing;
}
void ProjectImageServices::stage_movie_frame(std::uint64_t generation,std::uint32_t member,std::uint32_t frame,bool loop) {
    const auto& row=prepared_.at(generation);
    if(!row.movie)throw std::runtime_error("Expected a selected source movie");
    auto next=row.movie->load(member,frame,true,loop);
    staged_frame_=std::move(next);staged_generation_=generation;staged_member_=member;staged_number_=frame;
}
void ProjectImageServices::commit_image(std::uint64_t generation) noexcept {
    const auto& row=prepared_.at(generation);
    if(staged_frame_ && generation==staged_generation_) {
        current_frame_=std::move(staged_frame_); visible_member_=staged_member_;visible_frame_=staged_number_;
        staged_generation_=0;
    } else {current_frame_=row.frames.at(row.plan.primary_virtual_name);visible_member_=visible_frame_=0;}
    if(release_after_display_ && current_generation_!=generation) {
        prepared_.erase(current_generation_);release_after_display_=false;
    }
    current_generation_=generation;
}
void ProjectImageServices::capture_field(GuestMemory& m,std::uint32_t destination,unsigned field) const {
    if(!current_frame_ || current_frame_->width!=640 || current_frame_->height!=448 || field>1)
        throw std::runtime_error("13CD20 needs a committed 640x448 native image for field capture");
    const auto overlay=visible_sab(m);
    RasterFrame layered;
    if(!overlay.bytes.empty()){layered=*current_frame_;draw_sab_layer(layered,m,overlay);}
    const auto src=std::span(overlay.bytes.empty()?current_frame_->rgba:layered.rgba);
    for(unsigned y=0;y<224;++y)m.write_bytes(destination+y*2560,src.subspan((2*y+field)*2560,2560));
}
}
