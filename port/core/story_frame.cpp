#include "story_frame.hpp"
#include "control_transfer.hpp"
#include "media_command.hpp"
#include "recovered.hpp"
#include "timechart_native.hpp"
#include "name_entry.hpp"
#include "actor_choice.hpp"
#include "mystery_panel.hpp"
#include <array>
#include <stdexcept>

namespace kx3 {
namespace {
using u32=std::uint32_t;
struct FrameGlyphs final : TextPresentationBackend {
    std::vector<TextGlyphEvent> staged;
    std::optional<std::size_t> last_clear;
    void stage_page_clear() override { last_clear=staged.size(); }
    void stage_glyph_events(std::span<const TextGlyphEvent> events) override {
        staged.insert(staged.end(),events.begin(),events.end());
    }
};

class MediaFrame {
    MediaCommandBackend* backend_;
    bool committed_=false;
public:
    explicit MediaFrame(MediaCommandBackend* backend):backend_(backend) {
        if(backend_) backend_->begin_frame();
    }
    ~MediaFrame(){if(backend_) backend_->end_frame(committed_);}
    void commit() noexcept {committed_=true;}
};

// The three outer source semaphores protect the same single-owner native game
// session. Their guest owner bookkeeping remains visible during script calls.
// A pending or priority-inheriting PS2 task needs its own scheduler adapter.
void check_outer_locks(const GuestMemory& m,const std::array<u32,3>& locks) {
    std::array<u32,3> handles{};
    for(unsigned i=0;i<locks.size();++i) {
        const u32 lock=locks[i], handle=m.read_u32(lock);
        if(!handle || handle>=0x80000000 || m.read_u32(lock+4)!=0xffffffffu || m.read_u32(lock+12)!=0)
            throw std::runtime_error("113148 needs an available non-priority source semaphore");
        for(unsigned j=0;j<i;++j)
            if(handles[j]==handle)throw std::runtime_error("113148 outer semaphores alias");
        handles[i]=handle;
    }
}
}

void ManagerFrameBindings::sample(GuestMemory& m,ExecutionServices& services) const {
    mystery::complete_requests(m,&services);
    if(const auto* input=services.choice_input) {
        // Primary physical pad record. 15F168 turns a held sample into one
        // cached edge mask. Multiple consumers in this frame see the same edge.
        constexpr u32 device=0x1e41c60;
        // 15EE40 copies word zero from the physical controller record. A host
        // sample represents a connected controller, including on idle frames.
        m.write_u32(device,1);
        const bool pointed=point_at_answer_cell(m,m.read_u32(0x235e40),input->name_index);
        const auto held=std::uint16_t(input->held | (pointed && input->name_confirm?0x2000:0));
        m.write_u16(device+8,held);
        m.write_u16(device+0xb8,held);
        m.write_u32(device+0xb4,1);
        // 14FB58 acquires the physical sample. 14FB6C calls 175B28, whose
        // tail jump to 175D98 selects the original pad owner before manager input.
        (void)run_vm_context(m,0x175d98,0,0,0,0,&services);
        if(menu_was_open)sample_chart_directions(m,input->held);
    }
}

void ManagerFrameBindings::finish(GuestMemory& m,u32 manager,ExecutionServices& services) const {
    if(menu_was_open)advance_system_menu(m,manager,&services);
    advance_actor_panel(m,&services);
    mystery::advance(m,&services);
}

StoryFrameResult StoryFrameDriver::advance(GuestMemory& m,u32 manager,MediaCommandBackend* media,
                                          ChoiceServices* choice,std::optional<ChoiceInput> input,
                                          const SystemMenuHost* system_menu,u32 screen_task_heap,
                                          const SoundDeviceStatus* sound_device,const MediaActiveServices* iso_files) {
    std::lock_guard guard(session_lock_);
    GuestMemory::AccessBudget budget(m,32'000'000);
    GuestMemory::Transaction transaction(m);
    MediaFrame media_frame(media);
    FrameGlyphs glyphs;
    StoryFrameResult result;
    ExecutionServices services{choice,media,&glyphs,input?&*input:nullptr,&result.choice_effects,
                               system_menu,&result.system_sounds,screen_task_heap,&result.system_record_requested,sound_device};
    ManagerFrameBindings bindings{result,system_menu && system_menu_view(m,manager).open};
    services.manager_frame=&bindings;
    services.iso_files=iso_files;
    retire_name_editor_tasks(m);
    retire_interval_tasks(m,screen_task_heap);
    check_outer_locks(m,{0x205588,0x2055a8,manager+0x48});
    (void)invoke_recovered(m,0x113148,manager,0,0,0,&services);
    result.glyphs=std::move(glyphs.staged);
    result.last_page_clear=glyphs.last_clear;
    transaction.commit();
    media_frame.commit();
    return result;
}
}
