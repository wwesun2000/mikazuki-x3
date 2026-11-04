#include "media_active.hpp"
#include "sab_animation.hpp"
#include "control_transfer.hpp"
#include "guest_memory.hpp"
#include <algorithm>
#include <bit>
#include <limits>
#include <stdexcept>

// Source-bound SLPM_664.52: media-active-v1 / media-active-leaf-v1 dossiers.
// This is source control/data recovery with an explicit modern I/O boundary,
// not a reproduction of PS2 semaphore/thread/file-cache allocator internals.
namespace kx3 {
namespace {
using u32 = std::uint32_t;
using u64 = std::uint64_t;
constexpr u32 loader = 0x206250, types = 0x22acc8;
void need(bool condition, const char* error) {
    if (!condition) throw std::runtime_error(error);
}
std::string read_string(const GuestMemory& m, u32 address, std::size_t limit = 128) {
    std::string result;
    for (std::size_t i = 0; i < limit; ++i) {
        const auto value = m.read_u8(address + static_cast<u32>(i));
        if (!value) return result;
        need(value >= 32 && value < 127, "media name outside verified ASCII source scope");
        result.push_back(static_cast<char>(value));
    }
    throw std::runtime_error("media name exceeds source buffer bound");
}
void write_string(GuestMemory& m, u32 address, const std::string& value) {
    for (std::size_t i = 0; i < value.size(); ++i)
        m.write_u8(address + static_cast<u32>(i), static_cast<std::uint8_t>(value[i]));
    m.write_u8(address + static_cast<u32>(value.size()), 0);
}
// 136630/1366A8 do not recognize a dot at the first byte.
std::size_t extension_at(const std::string& name) {
    const auto dot = name.rfind('.');
    return dot != std::string::npos && dot > 0 && dot + 1 < name.size()
        ? dot + 1 : std::string::npos;
}
std::string extension(const std::string& name) {
    const auto at = extension_at(name);
    return at == std::string::npos ? "" : name.substr(at);
}
std::string replacement(const std::string& name, const std::string& ext) {
    const auto at = extension_at(name);
    need(at != std::string::npos, "source136778 would write via null extension pointer");
    return name.substr(0, at) + ext;
}
u32 type_of(const GuestMemory& m, const std::string& name) {
    const auto ext = extension(name);
    for (u32 i = 0; i < 17; ++i) {
        const auto at = types + i * 68, type = m.read_u32(at);
        if (type == 16) return 0; // Original table sentinel.
        need(type == i, "source media type table differs from bound ELF");
        if (read_string(m, m.read_u32(at + 16), 16) == ext) return type;
    }
    throw std::runtime_error("missing source media type table sentinel");
}
std::string type_string(const GuestMemory& m, u32 type, u32 field) {
    const auto ptr = m.read_u32(types + type * 68 + field);
    return ptr ? read_string(m, ptr, 32) : "";
}
u32 audio_class(const GuestMemory& m, const std::string& name) {
    const auto ext = extension(name);
    for (u32 i = 0; i < 16; ++i) {
        const auto at = 0x22b460 + i * 8, ptr = m.read_u32(at);
        if (!ptr) return 0;
        if (ext == read_string(m, ptr, 16)) return m.read_u32(at + 4);
    }
    throw std::runtime_error("missing source audio extension table sentinel");
}
u32 numeric_sound(const std::string& name) {
    // 136A50/1369E8 source behavior, including its nonstandard hex conversion.
    std::size_t at = 0;
    if (name.size() > 2 && name.starts_with("0x")) at = 2;
    else if (name.size() > 1 && name[0] == '$') at = 1;
    if (at) {
        u32 value = 0, multiplier = 1;
        for (std::size_t i = name.size(); i > at; --i) {
            value += (static_cast<u32>(static_cast<unsigned char>(name[i - 1])) - 48u) * multiplier;
            multiplier <<= 4;
        }
        return value;
    }
    u32 value = 0;
    for (const auto ch : name) {
        const auto digit = static_cast<u32>(static_cast<unsigned char>(ch)) - 48u;
        if (digit >= 10) break;
        value = value * 10u + digit;
    }
    return value;
}
std::string normalize(const GuestMemory& m, const std::string& input) {
    auto name = input;
    for (u32 i = 0; i < 16; ++i) {
        const auto ext = type_string(m, type_of(m, name), 20);
        if (ext.empty()) return name;
        name = replacement(name, ext);
    }
    throw std::runtime_error("cyclic source extension replacement");
}
MediaDecodedKind decoded_kind(u32 type, u32 sound_class) {
    if (sound_class) return MediaDecodedKind::Audio;
    if (type == 6) return MediaDecodedKind::Image;
    if (type >= 2 && type <= 5) return MediaDecodedKind::Video;
    return MediaDecodedKind::Data;
}
bool signed_less(u32 left, u32 right) {
    return (left ^ 0x80000000u) < (right ^ 0x80000000u);
}
void publish_audio_ids(GuestMemory& m, const SourceAudioPlan& audio) {
    // 1375D8 append-only metadata pool. Existing duplicates/order are preserved.
    const auto old = m.read_u32(loader + 0xdbc);
    for (std::size_t i = old; i < audio.source_pool_ids.size(); ++i) {
        m.write_u32(loader + 0xdbc, static_cast<u32>(i + 1));
        m.write_u32(loader + 0xdc0 + static_cast<u32>(i) * 4, audio.source_pool_ids[i]);
    }
    if (audio.retain_ids.empty()) return; // Exact1378B0 early return.
    // Source picks the strictly oldest signed timestamp, retaining first on ties.
    u32 oldest = 0x7fffffffu, selected = 0;
    for (u32 i = 0; i < 2; ++i) {
        const auto value = m.read_u32(0x206f7c + i * 4);
        if (signed_less(value, oldest)) { oldest = value; selected = i; }
    }
    for (std::size_t i = 0; i < audio.retain_ids.size(); ++i)
        m.write_u32(0x206f8c + selected * 0x40 + static_cast<u32>(i) * 4, audio.retain_ids[i]);
    const auto serial = m.read_u32(0x206f78) + 1;
    m.write_u32(0x206f78, serial);
    m.write_u32(0x206f84 + selected * 4, static_cast<u32>(audio.retain_ids.size()));
    m.write_u32(0x206f7c + selected * 4, serial);
    // 1403C0 worker IPC is replaced by the completed host audio preparation.
}
}

static SourceResourcePlan scene_resource_plan(GuestMemory& m, const MediaRequest& request,
                                     const MediaActiveServices& services) {
    need(request.auxiliary == 0 && request.kind == 0, "nonstandard scene preparation is unrecovered");
    need(request.descriptor != 0, "source lookup missed: active null descriptor");
    SourceResourcePlan plan;
    plan.scene_token = read_string(m, request.token_address, 23);
    need(std::vector<std::uint8_t>(plan.scene_token.begin(), plan.scene_token.end()) == request.token_bytes,
         "media request token changed before planning");
    const bool preview=m.read_u32(loader+0x5c8)!=0;
    const auto count = m.read_u16(request.descriptor);
    need(count <= 32, "descriptor exceeds original temporary row storage");
    auto cursor = request.descriptor + 2;
    for (u32 i = 0; i < count; ++i) {
        SourceMediaAsset asset;
        asset.original_name = read_string(m, cursor, 23);
        need(!asset.original_name.empty(), "empty source dependency name");
        cursor += static_cast<u32>(asset.original_name.size()) + 1;
        auto name = asset.original_name;
        asset.preview_substitution=preview && resolve_preview_filename(m,services,name,plan.preview_virtual_name);
        if(!asset.preview_substitution){
            // 1384B0 calls 137CA8 only when 137B98 returns zero.
            const auto normal = normalize(m, name);
            const auto normal_type = type_of(m, normal);
            const auto fallback = type_string(m, normal_type, 48);
            if (!fallback.empty()) {
                const auto candidate = type_string(m, normal_type, 12) + normal;
                if (!services.source_file_size(candidate)) name = fallback;
            }
        }
        for (u32 j = 0; j < 16; ++j) {
            const auto type = type_of(m, name), at = types + type * 68;
            asset.source_type = type;
            asset.flags |= m.read_u32(at + 36);
            const auto ext = type_string(m, type, 20);
            if (ext.empty()) break;
            name = replacement(name, ext);
            need(j != 15, "cyclic source resource normalization");
        }
        asset.resolved_name = name;
        asset.virtual_name = type_string(m, asset.source_type, 12) + name;
        need(name.size() < 23 && asset.virtual_name.size() < 25, "source resource row name/path overflow");
        asset.primary = m.read_u32(types + asset.source_type * 68 + 32) != 0;
        asset.resident_record = m.read_u32(types + asset.source_type * 68 + 28) == 0;
        asset.source_audio_class = audio_class(m, name);
        need(asset.source_audio_class <= 2, "unknown source audio classification");
        asset.required_kind = decoded_kind(asset.source_type, asset.source_audio_class);
        if (asset.source_audio_class != 1) {
            asset.source_size_bytes = services.source_file_size(asset.virtual_name);
            need(asset.source_size_bytes != 0, "original encoded resource is missing");
        }
        plan.assets.push_back(std::move(asset));
    }
    if (std::none_of(plan.assets.begin(), plan.assets.end(), [](const auto& a) { return a.primary; }))
        throw std::runtime_error("implicit default-primary branch has undefined source scratch flags; not admitted");
    // 138638 swaps pairs by source type. This is not stable_sort.
    for (std::size_t i = 0; i + 1 < plan.assets.size(); ++i)
        for (std::size_t j = i + 1; j < plan.assets.size(); ++j)
            if (plan.assets[j].source_type < plan.assets[i].source_type)
                std::swap(plan.assets[i], plan.assets[j]);
    for (const auto& asset : plan.assets)
        if (asset.primary && plan.primary_virtual_name.empty()) plan.primary_virtual_name = asset.virtual_name;
    need(plan.primary_virtual_name.size() < 23, "source primary path overlaps preview buffer");
    const auto pool_count = m.read_u32(loader + 0xdbc);
    need(pool_count <= 16, "original retained sound pool outside verified capacity");
    for (u32 i = 0; i < pool_count; ++i)
        plan.audio.source_pool_ids.push_back(m.read_u32(loader + 0xdc0 + i * 4));
    for (const auto& asset : plan.assets) {
        if (!asset.resident_record) continue;
        if (asset.source_audio_class == 2) {
            if (plan.audio.prepare_bgm.empty()) plan.audio.prepare_bgm.push_back(asset.resolved_name);
        } else if (asset.source_audio_class == 1 && plan.audio.retain_ids.size() < 16) {
            const auto id = numeric_sound(asset.resolved_name);
            plan.audio.retain_ids.push_back(id);
            // Original175F78(20) is source constant0; 1B1FD0 gates metadata.
            // 136A50 returns a sign-extended32 integer; 1B1FD0 compares its
            // signed64 value against999. High-bit IDs must not query the bank.
            if (id > 999 && id <= 0x7fffffffu && services.sound_retention_flag(id) &&
                std::find(plan.audio.source_pool_ids.begin(), plan.audio.source_pool_ids.end(), id) == plan.audio.source_pool_ids.end()) {
                need(plan.audio.source_pool_ids.size() < 16, "source retained sound pool overflow");
                plan.audio.source_pool_ids.push_back(id);
            }
        }
    }
    for (const auto id : plan.audio.source_pool_ids)
        if (plan.audio.retain_ids.size() < 16 &&
            std::find(plan.audio.retain_ids.begin(), plan.audio.retain_ids.end(), id) == plan.audio.retain_ids.end())
            plan.audio.retain_ids.push_back(id);
    return plan;
}

SourceResourcePlan plan_active_media(GuestMemory& m, const MediaRequest& request, const MediaActiveServices& services) {
    need(request.active != 0, "expected an active media request");
    return scene_resource_plan(m,request,services);
}

void validate_media_receipt(const SourceResourcePlan& plan, const MediaPrepareReceipt& receipt) {
    need(receipt.prepared_generation != 0 && receipt.current_presentation_unchanged,
         "media preload lacks an owned prepared generation or changed current presentation");
    need(receipt.assets.size() == plan.assets.size(), "media receipt does not cover all source dependencies");
    need(receipt.prepared_bgm == plan.audio.prepare_bgm && receipt.retained_sound_ids == plan.audio.retain_ids,
         "media receipt omits original audio preparation/preservation");
    for (std::size_t i = 0; i < plan.assets.size(); ++i) {
        const auto& asset = plan.assets[i]; const auto& done = receipt.assets[i];
        need(done.virtual_name == asset.virtual_name && done.source_size_bytes == asset.source_size_bytes &&
             done.decoded_kind == asset.required_kind, "media receipt identity/type differs from source plan");
        need(done.source_sha256.size() == 64 && std::all_of(done.source_sha256.begin(), done.source_sha256.end(),
             [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }), "media receipt lacks original source SHA256");
        need(done.decoded_bytes != 0, "empty/log-only media receipt rejected");
        if (done.decoded_kind == MediaDecodedKind::Image) {
            need(done.width > 0 && done.height > 0 && done.width <= 8192 && done.height <= 8192 && done.frame_count == 1,
                 "invalid decoded image shape");
            need(done.decoded_bytes == u64(done.width) * done.height * 4, "image receipt is not a complete RGBA frame");
        } else if (done.decoded_kind == MediaDecodedKind::Video)
            need(done.width && done.height && done.frame_count, "video not actually decoded/prepared");
        else if (done.decoded_kind == MediaDecodedKind::Audio)
            need(done.sample_count, "audio not actually decoded/prepared");
    }
}

SourceMediaActiveBackend::Checkpoint SourceMediaActiveBackend::checkpoint() const {
    if(frame_active_) throw std::logic_error("Cannot save a pending scene transaction");
    return {pending_.descriptor,pending_.generation,selected_generation_,stream_end_reported_,movie_};
}
void SourceMediaActiveBackend::restore_checkpoint(const Checkpoint& state) {
    if(frame_active_ || bool(state.pending_descriptor)!=bool(state.pending_generation))
        throw std::runtime_error("Invalid scene worker checkpoint");
    pending_={state.pending_descriptor,state.pending_generation};
    selected_generation_=state.selected_generation;
    movie_=state.movie;
    if(movie_.active) {
        const auto* presenter=services_.image_presenter();
        if(!presenter)throw std::runtime_error("Saved playing movie needs its original decoder");
        auto test=movie_;advance_movie_clock(test,presenter->movie_timings(selected_generation_));
    }
    stream_end_reported_=state.end_reported;
}

void SourceMediaActiveBackend::begin_frame() {
    if (frame_active_) throw std::logic_error("Nested source media frame");
    saved_prefetched_=prefetched_;
    frame_generations_.clear();
    saved_pending_=pending_;
    saved_selected_=selected_generation_;
    saved_stream_end_reported_=stream_end_reported_;
    saved_movie_=movie_;
    staged_presentation_=0;
    frame_active_ = true;
}

void SourceMediaActiveBackend::restore_preload(const std::string& token,std::uint64_t generation) {
    if(frame_active_ || !generation || token.empty())throw std::invalid_argument("Invalid saved source prefetch");
    auto [at,added]=prefetched_.try_emplace(token,generation);
    if(!added){
        services_.discard_prepared(at->second);
        at->second=generation;
    }
}
void SourceMediaActiveBackend::end_frame(bool commit) noexcept {
    if (!commit) {
        for (auto it=frame_generations_.rbegin(); it!=frame_generations_.rend(); ++it)
            services_.rollback_prepared(*it);
        pending_=saved_pending_;
        selected_generation_=saved_selected_;
        stream_end_reported_=saved_stream_end_reported_;
        movie_=saved_movie_;
        prefetched_.swap(saved_prefetched_);
        if(auto* presenter=services_.image_presenter())presenter->forget_staged_frame();
    } else {
        if(staged_presentation_) services_.image_presenter()->commit_image(staged_presentation_);
        if(saved_selected_ && saved_selected_ != selected_generation_) services_.discard_prepared(saved_selected_);
        auto release_unused=[&](std::uint64_t id){
            if(id==pending_.generation || id==selected_generation_)return;
            for(const auto& entry:prefetched_)if(entry.second==id)return;
            services_.discard_prepared(id);
        };
        for(const auto& entry:saved_prefetched_)release_unused(entry.second);
        for(const auto id:frame_generations_)release_unused(id);
    }
    frame_generations_.clear();
    saved_prefetched_.clear();
    frame_active_ = false;
}

static void publish_descriptor_rows(GuestMemory& m, const SourceResourcePlan& plan) {
    m.write_u32(loader + 0x8c, 0); // 1384EC; implicit fallback excluded.
    m.write_u8(loader + 0xe44, 0); m.write_u8(loader + 0xe5b, 0);
    write_string(m, loader + 0xe44, plan.primary_virtual_name);
    write_string(m, loader + 0xe5b, plan.preview_virtual_name);
    u32 row = 0;
    for (const auto& asset : plan.assets) {
        if (!asset.resident_record) continue;
        const auto at = 0x23ba50 + row++ * 60;
        write_string(m, at, asset.resolved_name);
        write_string(m, at + 23, asset.virtual_name);
        m.write_u32(at + 48, asset.source_type);
        m.write_u32(at + 52, asset.source_audio_class ? 0 : asset.source_size_bytes);
        m.write_u32(at + 56, asset.flags);
        // Bytes not initialized by the original local row remain opaque;
        // no invented original stack garbage is copied into persistent RAM.
    }
    m.write_u32(0x238718, row);
}

namespace {
bool cue_tasks_busy(const GuestMemory& m) {
    // 139028 -> 138F08,138EB8,139078. Native execution holds the session lock.
    u32 cursor=m.read_u32(0x206dd0), end=m.read_u32(0x206dcc);
    need(cursor<8 && end<8,"138F08 invalid cue queue indices");
    for(;cursor!=end;cursor=(cursor+1)%8)
        if(m.read_u32(0x206ddc+cursor*0x34)) return true;
    return m.read_u32(0x238724) || m.read_u32(0x23871c)!=m.read_u32(0x238720) ||
           m.read_u32(0x206dd4) || m.read_u32(0x238730);
}
void clear_framebuffer(GuestMemory& m) { // 13D048, paired 64-bit SDs.
    const u32 base=m.read_u32(0x236114);
    need(base>=0x240000 && !(base&15) && base<=GuestMemory::size-0x118000 &&
         m.read_u32(0x236118)==base+0x8c000, "13D048 needs allocated source framebuffer 13BF98");
    const std::array<std::uint8_t,4096> zero{};
    for(u32 offset=0;offset<0x118000;offset+=zero.size()) m.write_bytes(base+offset,zero);
}
void reset_scene(GuestMemory& m,const SourceResourcePlan& plan) {
    // 138930, normal single-IPU descriptor. Other dependency types route
    // through different scene model, movie, sound and effect setup.
    m.write_u32(0x206824,0);
    for(u32 i=0;i<16;++i)m.write_u32(0x206828+i*4,0);
    m.write_u32(0x206258,m.read_u32(0x2360d0));
    // 13D3F8 default camera and render control fields.
    for(u32 i=0;i<12;++i)m.write_u32(0x206270+4*i,0);
    for(u32 a:{0x206370,0x206374,0x206378,0x2067ec,0x20637c,0x206388,0x20638c,0x206398,0x206498})
        m.write_u32(a,0);
    m.write_u32(0x20627c,m.read_u32(0x2361a8)); m.write_u32(0x206274,m.read_u32(0x2361ac));
    m.write_u32(0x2062a0,m.read_u32(0x2361b0)); m.write_u32(0x206380,128);
    m.write_u32(0x206384,m.read_u32(0x2361b4)); m.write_u32(0x206390,m.read_u32(0x2361b8));
    m.write_u32(0x206394,m.read_u32(0x2361bc)); m.write_u32(0x20649c,m.read_u32(0x2361c0));
    m.write_u32(0x2064a0,1);
    for(u32 a:{0x2062a4,0x206254,0x2062e0,0x206328,0x206324,0x206344,0x206338,0x2062d4,0x2064ac,0x2062cc})
        m.write_u32(a,0);
    m.write_u32(0x20633c,m.read_u32(0x236450)); m.write_u32(0x206340,m.read_u32(0x236454));
    if(m.read_u32(0x236484))run_vm_context(m,0x147928,0,0,0,0,nullptr); // 1389BC releases the active descriptor.
    m.write_u32(0x236488,0xffffffff);
    m.write_u32(0x2367c0,0); m.write_u32(0x2367c4,0xffffffe0); m.write_u32(0x2367cc,0xffffffff);
    m.write_u32(0x2367c8,0xffffffe0); m.write_u32(0x2367d0,0);
    for(u32 i=0;i<10;++i)m.write_u32(0x23eaa8+i*4,0);
    u32 index=0;
    for(const auto& asset:plan.assets) {
        if(!asset.resident_record)continue; // Source type5/PSS is streamed independently.
        const auto table=types+asset.source_type*68;
        need(asset.resident_record && !m.read_u32(table+28),"138930 resident type mismatch");
        if((asset.flags&3)==1) m.write_u32(0x2062a4,1);
        m.write_u32(0x206ba4+4*index,m.read_u32(table+44));
        write_string(m,0x206868+0x17*index,asset.virtual_name);
        m.write_u32(0x206c34+4*index,asset.source_type);
        const u32 count=0x206828+asset.source_type*4;
        m.write_u32(count,m.read_u32(count)+1);
        m.write_u32(0x206824,++index);
    }
    write_string(m,0x2070c2,plan.primary_virtual_name);write_string(m,0x2070d9,plan.preview_virtual_name);
}
}

void capture_source_display_field(GuestMemory& m,unsigned pass,unsigned display_field,
                                 const std::function<void(u32,unsigned)>& submit) {
    const u32 left=m.read_u32(0x236104);
    if(!left || m.read_u32(0x236108)!=pass || !m.read_u32(0x2062bc))return;
    if(std::bit_cast<std::int32_t>(left)>=3){m.write_u32(0x236104,left-1);return;}
    need(display_field<=1,"13CD20 invalid display field");
    const auto trials=m.read_u32(0x23610c)+1;
    m.write_u32(0x23610c,trials);
    auto field=[&](unsigned destination) {
        const auto target=m.read_u32(0x236114+4*destination);
        need(target>=0x240000 && target<=GuestMemory::size-0x8c000,"13CCA0 missing original capture allocation");
        submit(target,display_field);
    };
    if(std::bit_cast<std::int32_t>(trials)>std::bit_cast<std::int32_t>(m.read_u32(0x236188))) {
        field(0);field(1);m.write_u32(0x236104,0);return;
    }
    if(!display_field) {
        if(left==2){field(0);m.write_u32(0x236104,1);}
        else if(left==1)m.write_u32(0x236104,2);
    } else if(left==1){field(1);m.write_u32(0x236104,0);}
}

void SourceMediaActiveBackend::step_deferred(GuestMemory& m) {
    const auto descriptor=m.read_u32(loader+0x5bc);
    auto state=m.read_u32(loader);
    if(state==8 || (!state && !descriptor)) return;
    need(frame_active_,"137D78 requires a transactional media frame");
    if(!state) { // 145B80 marks a new batch.
        m.write_u32(0x238768,0); m.write_u32(0x238764,m.read_u32(0x238764)+1);
        m.write_u32(loader,1); m.write_u8(0x23b9e8,0); state=1;
    }
    if(state==1 && cue_tasks_busy(m)) return;
    const auto token=read_string(m,loader+0xa74,23);
    const MediaRequest request{0x137578,descriptor,loader+0xa74,{token.begin(),token.end()},0,0,0};
    const auto plan=scene_resource_plan(m,request,services_);
    unsigned image_count=0;
    for(const auto& asset:plan.assets) {
        if(asset.primary && ((asset.source_type==6 && asset.required_kind==MediaDecodedKind::Image) ||
                            (asset.source_type>=3 && asset.source_type<=5 && asset.required_kind==MediaDecodedKind::Video)))
            ++image_count;
        else need((asset.source_type==10 && !asset.primary && asset.required_kind==MediaDecodedKind::Data) ||
                  ((asset.source_audio_class==1 || asset.source_audio_class==2) && asset.required_kind==MediaDecodedKind::Audio),
                  "137D78: unsupported original scene asset type");
        // Original type 2 (.m2s) normalizes to 3 (.m2v) in 1384B0.
        // Its additional flag bit 2 still controls 138930's looping field.
        const bool m2s=asset.source_type==3 && type_of(m,asset.original_name)==2 &&
                       asset.flags==3 && normalize(m,asset.original_name)==asset.resolved_name;
        need((asset.resident_record || asset.source_type==5) && (asset.original_name==asset.resolved_name || m2s || asset.preview_substitution),
             "137D78: unresolved source fallback or nonresident scene asset");
    }
    need(image_count==1 && !plan.fallback_primary && plan.assets.size()<36,
         "137D78 requires one primary movie/image and an in-bounds original dependency list");
    if(state==1) {
        publish_descriptor_rows(m,plan); // 1384B0, before reset of current scene.
        for(u32 i=0;i<37;++i)for(u32 base:{0x23b820u,0x23b8b8u,0x23b950u})m.write_u32(base+i*4,0);
        const auto old=read_string(m,0x2070c2,23);
        // 1374C0 checks the type table's +3C before comparing the previous
        // primary/preview strings against the new primary.
        const bool reuse=!m.read_u32(loader+0x5c8) && !m.read_u32(loader+0x5d0) &&
            m.read_u32(types+type_of(m,plan.primary_virtual_name)*68+60) && (old==plan.primary_virtual_name ||
                                    read_string(m,0x2070d9,23)==plan.primary_virtual_name);
        m.write_u32(0x2062a8,reuse);
        if(!reuse) {
            need(!m.read_u32(0x237e78),"13F010 needs original decoder-task stop");
            m.write_u8(0x23d320,0);
            // 1950F0 posts decoder stop bit 2. Any host read-ahead stays
            // private until the source clock explicitly requests a picture.
            if(movie_.active) { movie_.loop=false;movie_.active=false;stream_end_reported_=true; }
        }
        if(!m.read_u32(loader+0x5c0))clear_framebuffer(m);
        else if(!m.read_u32(loader+0x5c4)) {
            m.write_u32(0x236108,0);m.write_u32(0x236104,m.read_u32(0x23618c));m.write_u32(0x23610c,0);
            m.write_u32(loader,2); state=2;
        }
    }
    if(state==2 && m.read_u32(0x236104))return; // 13C018 polls, 13CD20 runs in the render passes.
    if(state==1 || state==2) {
        reset_scene(m,plan);
        m.write_u32(loader,3); // 137E94..137EAC yields to the next worker update.
        return;
    }
    if(state==3) {
        // 13F068: the native service owns its codec. With no previous
        // clip to drain, the original 195A80 path returned 5.
        m.write_u32(0x2062b8,0); m.write_u32(0x2062bc,0);
        m.write_u32(0x206324,0); m.write_u32(0x206328,0);
        const auto rows=m.read_u32(0x206824);
        m.write_u32(0x23870c,1+rows); m.write_u32(0x238710,0); m.write_u32(0x238714,0);
        m.write_u32(0x23b820,0x22b420); m.write_u32(0x23b8b8,0x5c0000); // 13F1C8 decoder work buffer.
        u32 i=0;
        for(const auto& asset:plan.assets) {
            if(!asset.resident_record)continue;
            m.write_u32(0x23b824+4*i,0x206868+0x17*i);
            m.write_u32(0x23b8bc+4*i,asset.source_audio_class ? 0xffffffffu : asset.source_size_bytes);
            m.write_u32(0x23b954+4*i,m.read_u32(0x206ba4+4*i));
            ++i;
        }
        for(u32 i=0;i<plan.audio.retain_ids.size();++i)m.write_u32(0x23ba00+i*4,plan.audio.retain_ids[i]);
        m.write_u32(0x238710,u32(plan.audio.retain_ids.size()));
        // Owned native file/cache/codec work replaces PS2 file batch,
        // semaphores and IPU hardware. Receipt must include the actual pixels.
        const auto receipt=services_.preload(plan);
        try {
            validate_media_receipt(plan,receipt);
            frame_generations_.push_back(receipt.prepared_generation);
        } catch(...) { services_.rollback_prepared(receipt.prepared_generation); throw; }
        pending_={descriptor,receipt.prepared_generation};
        std::vector<SabBlob> overlays;
        for(const auto& asset:plan.assets)if(asset.source_type==10)
            overlays.push_back({asset.resolved_name,services_.sab_file(receipt.prepared_generation,asset.virtual_name)});
        install_sab_files(m,overlays);
        publish_audio_ids(m,plan.audio);
        for(u32 a:{0x2067f0,0x2067f8,0x2067fc,0x206800,0x206808,0x236374})m.write_u32(a,0);
        m.write_u32(0x2067f4,0x2500);
        if(m.read_u32(0x2062a8)) {
            m.write_u32(0x2062bc,1); // 1383E4: original decoder is retained.
            for(u32 a:{0x2062b0,0x2062ac,0x206370,0x23621c,0x2062c0})m.write_u32(a,0);
            write_string(m,0x206d04,token);
            m.write_u32(loader,8);
            return;
        }
        // 13EFB8/13F038 post the decoded image for the media task.
        write_string(m,0x23d2a0,plan.primary_virtual_name);
        m.write_u32(0x236260,m.read_u32(0x2062a4));m.write_u32(0x23626c,1);
        m.write_u32(0x236268,0);m.write_u32(0x236270,0);
        m.write_u32(loader,6);
        return;
    }
    need(state==6,"137D78 loading phase outside native single-image service");
    need(pending_.descriptor==descriptor && pending_.generation!=0,
         "13F208 source scene lacks its decoded image generation");
    need(!m.read_u32(0x236270),"13F208 requires active decoder playback transition");
    // 13F208's filename submission and ready status 1, backed by the
    // completed original image decode. No cue has started playback.
    write_string(m,0x23d320,plan.primary_virtual_name);m.write_u8(0x23d2a0,0);
    m.write_u32(0x23626c,0);
    for(u32 a:{0x2062b0,0x2062ac,0x206370,0x23621c,0x2062c0})m.write_u32(a,0); // 138478
    write_string(m,0x206d04,token);
    m.write_u32(loader,8);
}

void SourceMediaActiveBackend::finish_deferred(GuestMemory& m) {
    need(frame_active_ && pending_.generation && pending_.descriptor==m.read_u32(loader+0x5bc),
         "135660 scene has no verified native completion");
    need(!m.read_u32(0x2064ac),"13EA88 needs an original model provider");
    m.write_u32(loader,0);m.write_u32(loader+0x5c4,0);m.write_u32(loader+0x68,1);
    m.write_u32(loader+0x5c0,pending_.descriptor);m.write_u32(loader+0x5bc,0);
    write_string(m,0x206d44,read_string(m,0x206d04,23));
    if(m.read_u32(0x23e270)==0xffffffffu) {
        m.write_u32(0x23e43c,0);m.write_u32(0x23e270,m.read_u32(0x23e258));
        m.write_u32(0x23e274,m.read_u32(0x23e268));
    }
    if(m.read_u32(loader+0x5c8)||m.read_u32(loader+0x88))clear_framebuffer(m);
    m.write_u32(loader+0x88,0);
    m.write_u32(0x2070f0,m.read_u32(0x2070f8)?128:0);m.write_u32(0x2070f8,0);
    m.write_u32(0x2070f4,0);m.write_u32(loader+0x80,0); // 138B30(0,0)
    adopt_completed_scene(m);
}

void SourceMediaActiveBackend::adopt_completed_scene(const GuestMemory& m) {
    need(frame_active_ && pending_.generation && !m.read_u32(loader) &&
         !m.read_u32(loader+0x5bc) && m.read_u32(loader+0x5c0)==pending_.descriptor,
         "1356F4 completed descriptor differs from the prepared scene");
    selected_generation_=pending_.generation;
    // This checked deferred load now owns the assets for that source token.
    // Retire the synchronous warm-up copy when the frame commits.
    prefetched_.erase(read_string(m,0x206d44,23));
    pending_={};
}

void SourceMediaActiveBackend::consume_image_start(GuestMemory& m) {
    // 13F208, decoder status 1, with 13EFF0's pending-play flag set.
    // Single decoded IPU: the host already has the genuine frame, so the
    // original IPU decoder's 194600/194F68 start becomes a native draw commit.
    auto* presenter=services_.image_presenter();
    need(frame_active_ && selected_generation_ && presenter && presenter->has_decoded_primary(selected_generation_),
         "13F208 playback needs the selected decoded original image");
    const auto clips=presenter->movie_timings(selected_generation_);
    const bool loop=m.read_u32(0x236260)!=0;
    need(m.read_u32(0x236268)==1 && !m.read_u32(0x23626c) && (!loop || !clips.empty()),
         "13F208 unexpected decoder playback flags");
    if(!m.read_u32(0x236270)) {
        const bool preroll=movie_.active && !clips.empty() && clips[movie_.member].video_start_sample>movie_.sample;
        need(preroll || presenter->single_frame_committed(selected_generation_),
             "13F208 has no submitted single-frame stream to finish");
        if(movie_.active) {
            const auto old=movie_;
            advance_movie_clock(movie_,clips);
            if(movie_.active && movie_.sample>=clips[movie_.member].video_start_sample &&
               (movie_.frame!=old.frame || movie_.member!=old.member ||
               (preroll && movie_.sample>=clips[movie_.member].video_start_sample))) {
                presenter->stage_movie_frame(selected_generation_,movie_.member,movie_.frame,movie_.loop);
                staged_presentation_=selected_generation_;
            }
            if(!movie_.active) stream_end_reported_=true;
            return;
        }
        // 1954A8 case 2: detecting EOS sets decoder+4B0=3 but returns 2.
        // Its next poll exposes status 3. 13F208 then consumes the pending
        // script wait; the displayed image stays resident after the stream ends.
        if(!stream_end_reported_) { stream_end_reported_=true; return; }
        m.write_u8(0x23d320,0);
        m.write_u32(0x236268,0);
        stream_end_reported_=false;
        return;
    }
    need(m.read_u32(0x236270)==1,"13F208 unexpected playback request");
    m.write_u32(0x23626c,0);m.write_u32(0x236270,0);
    m.write_u32(0x2062bc,1);m.write_u32(0x236264,m.read_u32(0x236260));
    movie_={};
    if(!clips.empty()) {
        // 195150 -> 195378 sets the decoder's loop bit when requested.
        movie_.active=true;movie_.loop=loop;
        if(clips[0].video_start_sample)return;
        presenter->stage_movie_frame(selected_generation_,0,0,loop);
    }
    stream_end_reported_=false;
    staged_presentation_=selected_generation_;
}

u64 SourceMediaActiveBackend::execute_active(GuestMemory& m, const MediaRequest& request) {
    const auto plan = plan_active_media(m, request, services_);
    const auto receipt = services_.preload(plan);
    try {
        validate_media_receipt(plan, receipt);
        write_string(m, loader + 0xa74, plan.scene_token); // 1376A8.
        publish_descriptor_rows(m,plan);
        // 146768 source file-batch bookmark. Worker allocation/semaphore/cache
        // records remain a replaceable platform service, not fabricated EE heap.
        if (m.read_u32(0x23e270) == 0xffffffffu) {
            m.write_u32(0x23e43c, 0);
            m.write_u32(0x23e270, m.read_u32(0x23e258));
            m.write_u32(0x23e274, m.read_u32(0x23e268));
        }
        publish_audio_ids(m, plan.audio);
        // For file-only source paths, 1453A8 returns1 for an existing ready
        // cache entry,0 after a new synchronous load;1378B0(count0) preserves it.
        // Audio helper chains are source-void; callers must not rely on v0.
        u64 result = 0;
        if (plan.audio.retain_ids.empty() && plan.audio.prepare_bgm.empty())
            for (std::size_t i = 0; i < plan.assets.size(); ++i)
                if (plan.assets[i].resident_record && !plan.assets[i].source_audio_class)
                    result = receipt.assets[i].reused_ready_cache ? 1 : 0;
        if (frame_active_) {
            frame_generations_.push_back(receipt.prepared_generation);
            prefetched_.insert_or_assign(plan.scene_token,receipt.prepared_generation);
        } else restore_preload(plan.scene_token,receipt.prepared_generation);
        return result;
    } catch (...) {
        services_.rollback_prepared(receipt.prepared_generation);
        throw;
    }
}
}
