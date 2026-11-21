#include "project_game.hpp"
#include "../../core/session_clock.hpp"
#include "../../core/scenario_checkpoint.hpp"
#include "raster_loader.hpp"
#include "../../core/save.hpp"
#include "../../core/save_lock.hpp"
#include "../../core/system_menu.hpp"
#include "../../core/staff_roll.hpp"
#include <bit>
#include <charconv>
#include <cstring>
#include <unordered_set>
#include <fstream>

namespace kx3::platform::windows {
namespace {
using u8=std::uint8_t;
using u32=std::uint32_t;
using u64=std::uint64_t;
constexpr std::size_t max_save_bytes=64u*1024*1024;
constexpr std::array<u8,8> magic{'K','X','3','W','I','N',9,0};
void check(bool ok,const char* message) { if(!ok)throw std::runtime_error(message); }

struct Writer {
    std::vector<u8> bytes;
    void word(u64 n,unsigned width=4) {
        for(unsigned i=0;i<width;++i)bytes.push_back(u8(n>>(8*i)));
    }
    void blob(std::span<const u8> b) {
        check(b.size()<=max_save_bytes && bytes.size()+b.size()+4<=max_save_bytes,"Save is too large");
        word(b.size());bytes.insert(bytes.end(),b.begin(),b.end());
    }
    void text(const std::string& s) {
        blob({reinterpret_cast<const u8*>(s.data()),s.size()});
    }
    void real(float f) { word(std::bit_cast<u32>(f)); }
};
struct Reader {
    std::span<const u8> data;
    std::size_t pos=0;
    std::span<const u8> take(std::size_t count) {
        check(count<=data.size()-pos,"Truncated session save");
        auto part=data.subspan(pos,count);pos+=count;return part;
    }
    u64 number(unsigned width) {
        u64 result=0;auto part=take(width);
        for(unsigned i=0;i<width;++i)result|=u64(part[i])<<(8*i);
        return result;
    }
    u32 word(){return u32(number(4));}
    u32 count(u32 maximum){const auto n=word();check(n<=maximum,"Invalid saved collection length");return n;}
    bool flag(){const auto f=number(1);check(f<=1,"Invalid saved boolean");return f!=0;}
    float real(){return std::bit_cast<float>(word());}
    std::string text(u32 max=128) {
        const auto part=take(count(max));
        check(std::find(part.begin(),part.end(),0)==part.end(),"NUL in session identifier");
        return std::string(part.begin(),part.end());
    }
};
std::array<u8,32> hash_bytes(std::string_view hex) {
    std::array<u8,32> result{};
    for(unsigned i=0;i<32;++i){
        unsigned int x=0;
        auto p=hex.data()+i*2;
        check(std::from_chars(p,p+2,x,16).ec==std::errc{},"Invalid source identity");
        result[i]=u8(x);
    }
    return result;
}
SaveIdentity identity() {
    return {hash_bytes("50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160"),
            hash_bytes("2a193cdbe97ba96faf0ad4d376a1d45b765aa99625895ff161f5102a5e85c95d"),1};
}
void ids(Writer& w,const std::vector<u32>& values) {
    w.word(values.size());for(auto id:values)w.word(id);
}
std::vector<u32> ids(Reader& r) {
    std::vector<u32> values(r.count(16));for(auto& id:values)id=r.word();return values;
}
void write_plan(Writer& w,const SourceResourcePlan& p) {
    w.text(p.scene_token);w.text(p.primary_virtual_name);w.text(p.preview_virtual_name);w.word(p.fallback_primary,1);
    w.word(p.assets.size());
    for(const auto& a:p.assets){
        w.text(a.original_name);w.text(a.resolved_name);w.text(a.virtual_name);
        w.word(a.source_type);w.word(a.source_size_bytes);w.word(a.flags);w.word(u32(a.required_kind));
        w.word(a.primary,1);w.word(a.source_audio_class);w.word(a.resident_record,1);
    }
    w.word(p.audio.prepare_bgm.size());for(const auto& name:p.audio.prepare_bgm)w.text(name);
    ids(w,p.audio.retain_ids);ids(w,p.audio.source_pool_ids);
}
SourceResourcePlan read_plan(Reader& r) {
    SourceResourcePlan p;
    p.scene_token=r.text();p.primary_virtual_name=r.text();p.preview_virtual_name=r.text();p.fallback_primary=r.flag();
    p.assets.resize(r.count(32));
    for(auto& a:p.assets) {
        a.original_name=r.text();a.resolved_name=r.text();a.virtual_name=r.text();
        a.source_type=r.word();a.source_size_bytes=r.word();a.flags=r.word();
        a.required_kind=MediaDecodedKind(r.count(u32(MediaDecodedKind::Data)));
        a.primary=r.flag();a.source_audio_class=r.count(2);a.resident_record=r.flag();
    }
    p.audio.prepare_bgm.resize(r.count(1));for(auto& name:p.audio.prepare_bgm)name=r.text();
    p.audio.retain_ids=ids(r);p.audio.source_pool_ids=ids(r);return p;
}
void write_glyph(Writer& w,const TextGlyphEvent& e) {
    const auto& s=e.source;
    w.word(s.source_entry);w.word(s.manager);w.word(s.font);w.word(s.source_address);
    w.word(s.source_unit,2);w.word(s.display_unit,2);w.word(s.ruby,1);
    w.word(e.node_address);w.word(e.metric_record);w.word(e.atlas_address);w.word(u32(e.x));w.word(u32(e.y));
    w.word(e.width);w.word(e.height);w.word(u32(e.resource_atlas));
    w.word(s.insertion_site);
}
TextGlyphEvent read_glyph(Reader& r,const GuestMemory& memory,u32 manager,unsigned version) {
    TextGlyphEvent e{};auto& s=e.source;
    s.source_entry=r.word();s.manager=r.word();s.font=r.word();s.source_address=r.word();
    s.source_unit=std::uint16_t(r.number(2));s.display_unit=std::uint16_t(r.number(2));s.ruby=r.flag();
    e.node_address=r.word();e.metric_record=r.word();e.atlas_address=r.word();
    e.x=std::bit_cast<std::int32_t>(r.word());e.y=std::bit_cast<std::int32_t>(r.word());
    e.width=r.word();e.height=r.word();e.resource_atlas=std::bit_cast<std::int32_t>(r.word());
    if(version>=8)s.insertion_site=r.word();
    if(s.insertion_site)(void)memory.bytes(s.insertion_site,1);
    check(s.manager==manager && s.font==memory.read_u32(manager+0x3c),"Mismatched saved text owner");
    (void)memory.bytes(s.source_address,1);
    if(e.node_address)(void)memory.bytes(e.node_address,56);
    if(e.metric_record)(void)memory.bytes(e.metric_record,12);
    return e;
}
}

void ProjectGame::save(const std::filesystem::path& destination) const {
    save_impl(destination,false);
}
void ProjectGame::recovery_save(const std::filesystem::path& path,bool background){
    if(pending_recovery_.valid()){
        if(background && pending_recovery_.wait_for(std::chrono::seconds(0))!=std::future_status::ready)return;
        // An explicit exit always gets a fresh write attempt, even after a failed periodic save.
        if(background)pending_recovery_.get();
        else pending_recovery_.wait();
    }
    if(!background){save(path);return;}
    std::vector<u8> metadata;
    save_impl({},false,std::nullopt,false,&metadata);
    auto snapshot=std::make_unique<CoreCheckpoint>();
    snapshot->manager=runtime_.manager;snapshot->logical_tick=logical_tick_;
    snapshot->memory.write_bytes(0,memory_.bytes(0,GuestMemory::size));
    const auto header=magic.size()+4+scenario_.size();
    pending_recovery_=std::async(std::launch::async,[path,header,metadata=std::move(metadata),snapshot=std::move(snapshot)]{
        Writer out;
        out.bytes.insert(out.bytes.end(),metadata.begin(),metadata.begin()+header);
        out.blob(encode_checkpoint(*snapshot,identity()));
        out.bytes.insert(out.bytes.end(),metadata.begin()+header,metadata.end());
        const auto digest=source_bytes_sha256(out.bytes);
        out.bytes.insert(out.bytes.end(),digest.begin(),digest.end());
        replace_save_file_atomic(path,out.bytes);
    });
}
void ProjectGame::save_from_menu(const std::filesystem::path& destination) const {
    const auto menu=system_menu_view(memory_,runtime_.manager);
    check(menu.open && menu.screen==14 && menu.can_request_save,"Original menu does not permit saving here");
    save_impl(destination,true);
}
void ProjectGame::save_auto_target(const std::filesystem::path& destination,u32 slot){
    save_impl(destination,false,slot);
    complete_auto_save_target(memory_,runtime_.manager,slot,false);
    autosave_to_original_card_=false;
}
void ProjectGame::save_impl(const std::filesystem::path& destination,bool resume_story,std::optional<u32> target,
                           bool record_committed,std::vector<u8>* history) const {
    check(frame_complete_ && !memory_.transaction_active(),"No complete game frame to save");
    Writer w;
    w.bytes.insert(w.bytes.end(),magic.begin(),magic.end());
    // V1–V9 published automatic records through the PC slot adapter. V10
    // carries the explicit player choice of the original card across restarts.
    if(autosave_to_original_card_ && !target)w.bytes[6]=10;
    w.text(scenario_);
    if(!history){
        CoreCheckpoint core;
        core.manager=runtime_.manager;core.logical_tick=logical_tick_;
        core.memory.write_bytes(0,memory_.bytes(0,GuestMemory::size));
        if(target)complete_auto_save_target(core.memory,core.manager,*target,true);
        else if(resume_story)prepare_system_save_resume(core.memory,core.manager);
        if(record_committed){
            core.memory.write_u32(0x239fa0,0);core.memory.write_u32(0x239fa4,0);
            core.memory.write_u32(0x239fb0,(core.memory.read_u32(0x239fb0)+1)%2);
        }
        w.blob(encode_checkpoint(core,identity()));
    }
    w.word(images_.prepared().size());
    for(const auto& [generation,asset]:images_.prepared()) {
        w.word(generation,8);write_plan(w,asset.plan);
    }
    w.word(images_.current_generation(),8);w.word(images_.next_generation(),8);w.word(images_.release_after_display(),1);
    w.word(images_.visible_member());w.word(images_.visible_frame());
    const auto state=backend_.checkpoint();
    check(!state.pending_descriptor || memory_.read_u32(0x20680c)==state.pending_descriptor,
          "Cannot save a scene worker with a stale pending descriptor");
    w.word(state.pending_descriptor);w.word(state.pending_generation,8);w.word(state.selected_generation,8);
    w.word(state.end_reported,1);
    w.word(state.movie.member);w.word(state.movie.frame);w.word(state.movie.remainder);
    w.word(state.movie.active,1);w.word(state.movie.loop,1);w.word(state.movie.sample,8);
    w.word(mixer_.voices().size());
    for(const auto& v:mixer_.voices()){
        w.word(v.id);w.word(v.stream);w.text(v.sound->source_hash);
        w.word(v.position_q12,8);w.word(v.delay,8);w.word(v.ramp_elapsed,8);w.word(v.ramp_length,8);
        w.real(v.left_begin);w.real(v.right_begin);w.real(v.left_end);w.real(v.right_end);
        w.word(v.loop,1);w.word(v.stopping,1);w.word(v.route,1);w.word(v.volume);w.word(u32(v.pan));
        w.real(v.pitch.current);w.real(v.pitch.step);w.real(v.pitch.target);
    }
    w.word(bool(mixer_.music()),1);
    if(mixer_.music()) {
        const auto& m=*mixer_.music();w.text(m.track->name);w.text(m.track->source_hash);
        w.word(m.frame,8);w.word(m.ramp_elapsed,8);w.word(m.ramp_length,8);
        w.real(m.from);w.real(m.to);w.word(m.stopping,1);
    }
    for(auto sample:audio_block_)w.word(std::uint16_t(sample),2);
    w.word(visible_text_.size());for(const auto& g:visible_text_)write_glyph(w,g);
    check(w.bytes.size()<=max_save_bytes-64,"Session save exceeds size limit");
    if(history){*history=std::move(w.bytes);return;}
    const auto digest=source_bytes_sha256(w.bytes);
    w.bytes.insert(w.bytes.end(),digest.begin(),digest.end());
    // The auto publisher already owns this edition's lock through the bank
    // export. A manual save may replace one of the same ten slot files.
    std::optional<SaveWriterLock> writer;
    if(!record_committed && !system_record_file_.empty() && destination.parent_path()==system_record_file_.parent_path()){
        std::filesystem::create_directories(destination.parent_path());
        auto lock=system_record_file_;lock+=".lock";
        writer.emplace(lock,"Save directory is busy");
    }
    replace_save_file_atomic(destination,w.bytes);
}

std::unique_ptr<ProjectGame> ProjectGame::load(const std::filesystem::path& root,std::string_view scenario,
                                               const std::filesystem::path& source) {
    std::ifstream file(source,std::ios::ate|std::ios::binary);
    const auto n=file.tellg();
    check(file && n>=72 && std::uint64_t(n)<=max_save_bytes,"Invalid session file size");
    std::vector<u8> encoded(static_cast<std::size_t>(n));
    file.seekg(0);check(bool(file.read(reinterpret_cast<char*>(encoded.data()),n)),"Incomplete session save read");
    file.close();
    Reader r{std::span(encoded).first(encoded.size()-64)};
    const auto hash=source_bytes_sha256(r.data);
    check(std::equal(hash.begin(),hash.end(),encoded.end()-64),"Session save checksum mismatch");
    auto game=decode_session(root,scenario,r.data);
    game->loaded_checkpoint_=source;
    game->loaded_checksum_=hash;
    return game;
}

std::optional<ProjectGame::DialoguePosition> ProjectGame::dialogue_wait() const {
    const auto& m=memory_;
    const auto ctx=m.read_u32(runtime_.manager+0x40);
    if(!ctx || (ctx!=m.read_u32(0x235f38) && ctx!=m.read_u32(0x235f34)) ||
       system_menu_view(m,runtime_.manager).open || visible_text_.empty())return {};
    const auto script=m.read_u32(runtime_.manager+0x38);
    return DialoguePosition{m.read_u32(script+0xd0),m.read_u32(script+0xd4),m.read_u32(script+0xd8)};
}

bool ProjectGame::can_read_previous() const {
    if(pages_.empty() || system_menu_view(memory_,runtime_.manager).open)return false;
    const auto pos=dialogue_wait();
    return !pos || *pos!=pages_.back().position || pages_.size()>1;
}

void ProjectGame::remember_page(DialoguePosition position){
    // In-session history shares unchanged RAM blocks, including all-zero blocks.
    // Disk saves keep their independent checksum and versioned representation.
    Page page{position,{},{},logical_tick_};
    save_impl({},false,std::nullopt,false,&page.bytes);
    static const auto zero=std::make_shared<const HistoryBlock>();
    constexpr auto count=GuestMemory::size/sizeof(HistoryBlock);
    page.blocks.reserve(count);
    for(unsigned i=0;i<count;++i){
        const auto source=memory_.bytes(i*sizeof(HistoryBlock),sizeof(HistoryBlock));
        const auto& previous=pages_.empty()?zero:pages_.back().blocks[i];
        if(!std::memcmp(previous->data(),source.data(),source.size()))page.blocks.push_back(previous);
        else{
            auto block=std::make_shared<HistoryBlock>();
            std::memcpy(block->data(),source.data(),source.size());
            page.blocks.push_back(std::move(block));
        }
    }
    pages_.push_back(std::move(page));
    std::unordered_set<const HistoryBlock*> unique;
    std::size_t bytes=0,keep=0;
    for(auto it=pages_.rbegin();it!=pages_.rend() && keep<32;++it){
        bytes+=it->bytes.size()+it->blocks.size()*sizeof(it->blocks.front());
        for(const auto& block:it->blocks)
            if(unique.insert(block.get()).second)bytes+=sizeof(HistoryBlock);
        if(keep>=2 && bytes>48u*1024*1024)break;
        ++keep;
    }
    while(pages_.size()>keep)pages_.pop_front();
}

StoryFrameResult ProjectGame::play_frame(std::unique_ptr<ProjectGame>& game,const std::filesystem::path& root,ChoiceInput input){
    const auto page=game->dialogue_wait();
    const bool back=(input.held&0x10)!=0;
    if(input.read_previous || (page && back)){
        input.held &= ~0x10u;
        if((input.read_previous || !game->back_down_) && game->can_read_previous()){
            const bool current=page && *page==game->pages_.back().position;
            const auto& previous=game->pages_[game->pages_.size()-1-current];
            auto restored=decode_session(root,game->scenario_,previous.bytes,&previous);
            // A player-requested rewind always lands on a manual wait. 121E50
            // stops auto via +808; 115C58 consumes +814 only while it is armed.
            restored->memory_.write_u32(restored->runtime_.manager+0x808,0);
            restored->memory_.write_u32(restored->runtime_.manager+0x814,0);
            restored->set_system_record_file(game->system_record_file_);
            restored->audio_enabled_=game->audio_enabled_;
            if(current)game->pages_.pop_back();
            restored->pages_=std::move(game->pages_);
            restored->back_down_=back;
            game.swap(restored);
            return {};
        }
    }
    game->back_down_=back;
    auto result=game->advance(input);
    const auto next=game->dialogue_wait();
    if(next && (game->pages_.empty() || game->pages_.back().position!=*next))game->remember_page(*next);
    return result;
}

std::unique_ptr<ProjectGame> ProjectGame::decode_session(const std::filesystem::path& root,std::string_view scenario,std::span<const u8> data,const Page* page){
    Reader r{data};
    auto header=r.take(magic.size());
    const unsigned version=header[6];
    check(std::equal(header.begin(),header.begin()+6,magic.begin()) && version>=1 && version<=10 && !header[7],
          "Unsupported session save version");
    check(r.text(8)==scenario,"Save belongs to another original scenario");
    auto core=[&]() -> CoreCheckpoint {
        if(!page)return decode_checkpoint(r.take(r.count(max_save_bytes)),identity());
        CoreCheckpoint restored;
        for(unsigned i=0;i<page->blocks.size();++i)
            restored.memory.write_bytes(i*sizeof(HistoryBlock),*page->blocks[i]);
        restored.manager=restored.memory.read_u32(0x235e40);
        restored.logical_tick=page->tick;
        return restored;
    }();
    auto game=std::make_unique<ProjectGame>(root,scenario);
    game->autosave_to_original_card_=version==10;
    check(core.manager==game->runtime_.manager && core.memory.read_u32(0x235e40)==core.manager,"Mismatched saved game manager");
    // Early sessions kept the ELF initializer 1 even when booting sn2/sn4.
    // Use the checked save header and the new disc session's original edition.
    // This covers old sessions already converted to V8 before credits existed.
    const auto disc_edition=game->memory_.read_u32(0x235b00);
    if(core.memory.read_u32(0x235b00)!=disc_edition){
        check(core.memory.read_u32(0x235b00)==1 && !core.memory.read_u32(credits::file_size),
              "Saved edition differs from its original scenario");
        core.memory.write_u32(0x235b00,disc_edition);
    }
    game->memory_.replace_contents(std::move(core.memory));game->logical_tick_=core.logical_tick;
    if(version<8 && !game->memory_.read_u32(0x2070fc))game->memory_.write_u32(0x2070fc,0x10c8d0);
    restore_missing_choice_bootstrap(game->memory_,core.manager,0x1350000,0x1350800);
    restore_missing_panel_modes(game->memory_,core.manager);
    // Early development saves predate these platform locks and the source RNG.
    // Seed only absent state; repeat loads of the same old save remain identical.
    initialize_clock_and_pad(game->memory_,static_cast<u32>(game->logical_tick_));
    game->install_system_tables(root); // Older session versions predate slot-5 installation.
    install_scenario_checkpoint(game->memory_);
    const auto generations=r.count(max_prepared_scenes);
    for(unsigned i=0;i<generations;++i){
        const auto generation=r.number(8);game->images_.restore_prepared(generation,read_plan(r));
    }
    const auto visible=r.number(8);const auto next=r.number(8);
    const bool deferred_release=r.flag();
    const auto visible_member=version>=2?r.word():0;
    const auto visible_frame=version>=2?r.word():0;
    game->images_.restore_display(visible,next,deferred_release,visible_member,visible_frame);
    SourceMediaActiveBackend::Checkpoint state{r.word(),r.number(8),r.number(8),r.flag()};
    if(version>=2) {
        state.movie.member=r.word();state.movie.frame=r.word();state.movie.remainder=r.word();
        state.movie.active=r.flag();state.movie.loop=r.flag();
        if(version>=5)state.movie.sample=r.number(8);
        else if(state.movie.active){
            const auto* target=game->images_.prepared().at(state.selected_generation).movie.get();
            if(target && target->audio){
                const auto& c=target->timing.at(state.movie.member);
                state.movie.sample=c.video_start_sample+(std::uint64_t(state.movie.frame)*60*c.fps_den+
                    state.movie.remainder)*800/c.fps_num;
            }
        }
    }
    auto known=[&](u64 g){return !g || game->images_.prepared().contains(g);};
    check(known(state.pending_generation) && known(state.selected_generation),"Unbound saved scene worker generation");
    bool finish_legacy_readback=false;
    if(state.pending_descriptor) {
        const auto& memory=game->memory_;
        (void)memory.bytes(state.pending_descriptor,2);
        if(memory.read_u32(0x20680c)!=state.pending_descriptor){
            // Through V8 the readback path ran the original descriptor transfer
            // without transferring ownership of the prepared ISO assets.
            check(version<=8 && state.pending_generation && !memory.read_u32(0x206250) &&
                  !memory.read_u32(0x20680c) && memory.read_u32(0x206810)==state.pending_descriptor,
                  "Saved loader/descriptor mismatch");
            const auto& token=game->images_.prepared().at(state.pending_generation).plan.scene_token;
            const auto committed=memory.bytes(0x206d44,token.size()+1);
            check(!token.empty() && token.size()<24 && !committed.back() &&
                  std::equal(token.begin(),token.end(),committed.begin()),"Saved committed scene token mismatch");
            finish_legacy_readback=true;
        }
    }
    game->backend_.restore_checkpoint(state);
    std::vector<std::pair<std::string,u64>> preloads;
    for(const auto& [id,group]:game->images_.prepared()){
        if(id!=visible && id!=state.pending_generation && id!=state.selected_generation)
            preloads.emplace_back(group.plan.scene_token,id);
    }
    for(const auto& [token,id]:preloads)game->backend_.restore_preload(token,id);
    if(finish_legacy_readback){
        game->backend_.begin_frame();
        game->backend_.adopt_completed_scene(game->memory_);
        game->backend_.end_frame(true);
    }
    std::vector<PlayingVoice> voices(r.count(128));
    std::map<u32,unsigned> legacy_routes;
    for(auto& v:voices){
        v.id=r.word();v.stream=r.word();const auto source_hash=r.text(64);
        v.sound=game->images_.open_bank_sound(v.id);
        check(v.sound->source_hash==source_hash,"Sound bank changed since save");
        v.position_q12=r.number(8);v.delay=r.number(8);v.ramp_elapsed=r.number(8);v.ramp_length=r.number(8);
        v.left_begin=r.real();v.right_begin=r.real();v.left_end=r.real();v.right_end=r.real();
        v.loop=r.flag();v.stopping=r.flag();
        if(version>=4){v.route=u32(r.number(1));v.volume=r.word();}
        if(version>=6)v.pan=std::bit_cast<std::int32_t>(r.word());
        if(version>=7){v.pitch.current=r.real();v.pitch.step=r.real();v.pitch.target=r.real();}
        else if(v.loop){
            if(version<4)v.route=v.sound->record.channels==2?v.stream:legacy_routes[v.id]++%2;
            const auto n=game->memory_.read_u32(0x2389e0);
            check(n<=8,"Invalid legacy looping voice table");
            for(u32 i=0;i<n;++i)if(game->memory_.read_u32(0x1e4c680+16*i)==v.id){
                if(version<4)v.volume=game->memory_.read_u32(0x1e4c684+16*i);
                v.pan=std::bit_cast<std::int32_t>(game->memory_.read_u32(0x1e4c688+16*i));break;
            }
        }
    }
    game->mixer_.restore_voices(std::move(voices));
    if(version>=3 && r.flag()) {
        PlayingMusic m;const auto name=r.text(), hash=r.text(64);
        m.track=game->images_.open_music(name);
        check(m.track->source_hash==hash,"BGM source changed since save");
        m.frame=r.number(8);m.ramp_elapsed=r.number(8);m.ramp_length=r.number(8);
        m.from=r.real();m.to=r.real();m.stopping=r.flag();
        game->mixer_.restore_music(std::move(m));
    }
    for(auto& sample:game->audio_block_)sample=std::bit_cast<std::int16_t>(std::uint16_t(r.number(2)));
    const auto glyphs=r.count(100000);
    game->visible_text_.reserve(glyphs);
    for(u32 i=0;i<glyphs;++i)game->visible_text_.push_back(read_glyph(r,game->memory_,core.manager,version));
    check(r.pos==r.data.size(),"Unexpected trailing session data");
    game->frame_complete_=true;
    return game;
}
}
