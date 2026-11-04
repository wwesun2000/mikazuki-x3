#include "recovered.hpp"
#include "scenario_checkpoint.hpp"
#include "screen_task.hpp"
#include "guest_memory.hpp"
#include "script_data.hpp"
#include "source_libc.hpp"
#include "choice.hpp"
#include "dispatch.hpp"
#include "manager_ops.hpp"
#include "media_command.hpp"
#include "choice_pipeline.hpp"
#include "particle_effect.hpp"
#include "sab_animation.hpp"
#include "mime_effect.hpp"
#include "control_transfer.hpp"
#include "text_commands.hpp"
#include "font_preferences.hpp"
#include "cue_command.hpp"
#include "cue_effect.hpp"
#include "record_scope.hpp"
#include "system_menu.hpp"
#include "timechart_native.hpp"
#include "name_entry.hpp"
#include "actor_choice.hpp"
#include "context_bridges.hpp"
#include "text_driver.hpp"
#include "manager_input.hpp"
#include "page_control.hpp"
#include "page_start.hpp"
#include "zero_bindings.hpp"
#include "literal_returns.hpp"
#include "tail_bindings.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace kx3 {
namespace {
thread_local unsigned call_depth=0;
struct CallDepthGuard {
    CallDepthGuard() {
        if(call_depth>=256) throw std::runtime_error("Native source-call depth limit exceeded");
        ++call_depth;
    }
    ~CallDepthGuard() {--call_depth;}
};
class NoExternalChoice final : public ChoiceServices {
public:
    bool supports_source(std::uint32_t) const override {return false;}
    std::uint64_t call_source(GuestMemory&,std::uint32_t,std::span<const std::uint64_t>) override {
        throw std::runtime_error("Choice source callback requires an explicit service");
    }
    bool supports_effect(ChoiceEffectKind) const override {return false;}
    bool glyph_animation_pending() const override {throw std::runtime_error("Choice readiness requires a real renderer");}
};
}
std::uint64_t invoke_recovered(GuestMemory& m, std::uint32_t entry,
                              std::uint32_t self, std::uint64_t a1,
                              std::uint64_t a2, std::uint64_t a3, ExecutionServices* services) {
    CallDepthGuard depth_guard;
    switch(entry){
#define KX3_MENU_ENTRY(address,fn) case address:
#include "scenario_text_entries.hpp"
#include "scenario_history_entries.hpp"
#include "story_glyphs_entries.hpp"
#include "story_contexts_entries.hpp"
#include "choice_preview_entries.hpp"
#include "readback_handlers_entries.hpp"
#include "answer_input_entries.hpp"
#include "chart_progress_entries.hpp"
#include "scenario_input_entries.hpp"
#include "interval_menu_entries.hpp"
#include "ending_menu_entries.hpp"
#include "settings_menu_entries.hpp"
#include "root_menu_entries.hpp"
#include "system_card_entries.hpp"
#undef KX3_MENU_ENTRY
    case 0x1358f8: // Shared by 114E50/114E90 and the recovered card UI.
        return run_vm_context(m,entry,self,a1,a2,a3,services);
    default:break;
    }
    switch (entry) {
#define KX3_VM_ENTRY(address) case address:
#include "vm_context_handlers.hpp"
#define KX3_MENU_ENTRY(address,fn) KX3_VM_ENTRY(address)
#include "mystery_panels_entries.hpp"
#include "scenario_branches_entries.hpp"
#undef KX3_MENU_ENTRY
#undef KX3_VM_ENTRY
        return run_vm_context(m,entry,self,a1,a2,a3,services);
    case 0x12c808:case 0x120768:return run_scenario_return(m,entry,self,a1,services);
    case 0x17c498:case 0x17c598:update_mime_effect(m,self,services);return 0;
    case 0x17e288:update_flash_effect(m,self);return 0;
    case 0x146960:case 0x1469e0:case 0x1397b0:case 0x146b50:case 0x146be0:case 0x146c18:
        return invoke_sab_animation(m,entry,self,std::uint32_t(a1),std::uint32_t(a2));
    case 0x183258:return create_snow_particles(m,self,std::uint32_t(a1),services);
    case 0x1833f8:update_snow_particles(m,self,services);return 0;
    case 0x104e10:return write_scenario_checkpoint(m,services);
    case 0x1536a8:
    case 0x153a70: {
        // Kernel wait/signal on single-owner serialized native execution. The
        // source also records the current thread and any priority to restore.
        // The RNG, pad and memory-card directory serialize on this worker.
        const bool sound_scan=self==0x210758 || self==0x207aa8;
        const auto manager=m.read_u32(0x235e40);
        const bool manager_lock=self==0x205588 || self==0x2055a8 || (manager && self==manager+0x48);
        if(self!=0x20c7d0 && self!=0x207c58 && self!=0x204bc0 && self!=0x2107c0 && self!=0x207140 && !sound_scan && !manager_lock)
            throw std::runtime_error("Unbound native semaphore client at 1536A8/153A70");
        // 1B012C and 153D48 create the two queue mutexes. Older sessions
        // may reach their first BGM query before these services exist.
        if(sound_scan && entry==0x1536a8 && (!m.read_u32(self) || m.read_u32(self)==UINT32_MAX)){
            m.write_u32(self,self==0x210758?10:11);m.write_u32(self+4,UINT32_MAX);
            m.write_u32(self+8,0);
        }
        const auto handle=m.read_u32(self), owner=m.read_u32(self+4);
        if(!handle || handle>=0x80000000u || m.read_u32(self+8))
            throw std::runtime_error("Uninitialized semaphore or unresolved priority restore");
        constexpr std::uint32_t native_worker=1;
        if(entry==0x1536a8 && owner==UINT32_MAX)m.write_u32(self+4,native_worker);
        else if(entry==0x153a70 && owner==native_worker)m.write_u32(self+4,UINT32_MAX);
        else throw std::runtime_error("Source semaphore still owned by another worker");
        m.write_u32(self+8,0);return 0;
    }
    case 0x19c910: {
        NoExternalChoice fallback;
        auto& choice=services && services->choice?*services->choice:fallback;
        choice_begin_label_transactional(m,self,a1,choice);
        return 0;
    }
    case 0x0019c868: {
        NoExternalChoice fallback;
        auto& choice = services && services->choice ? *services->choice : fallback;
        page_progress_label_transactional(m,self,a1,choice);
        return 0;
    }
    case 0x0012f1d0:
        return apply_page_font_preferences(m);
    case 0x0012a268:
        return apply_script_font_margin(m,a1);
    case 0x0012fa88:
        return apply_script_font_preference(m,a1);
    case 0x00204928:case 0x0011eba8: {
        const auto adjustment=m.read_u32(m.read_u32(self)-12);
        return invoke_recovered(m,entry==0x204928?0x120b48:0x11e608,self+adjustment,a1,a2,a3,services);
    }
    case 0x001fdc64: return source_strlen(m, self);
    case 0x001fdb50: return source_strcpy(m, self, a1);
    case 0x001fda0c: return source_strcmp(m, self, a1);
    case 0x001fc524: return source_memcpy(m, self, a1, a2);
    case 0x0011ec30:
    case 0x001114f0: case 0x00111560: case 0x001133a8: case 0x001133b0:
    case 0x00120250: case 0x00120300: case 0x00120308:
    case 0x001203e0: case 0x00120410: case 0x00120528: case 0x00120628:
    case 0x00113578: case 0x00132478:
        return invoke_dispatch(m, entry, self, a1, a2, a3, services);
    default: break;
    }
    const auto bridge=std::lower_bound(context_bridges.begin(),context_bridges.end(),entry,
        [](const auto& item,std::uint32_t addr){return item.entry<addr;});
    if(bridge!=context_bridges.end() && bridge->entry==entry){
        const auto target=std::uint32_t(a1);
        return invoke_recovered(m,m.read_u32(m.read_u32(target)+bridge->offset),target,self,a2,a3,services);
    }
    if (std::binary_search(zero_bindings.begin(), zero_bindings.end(), entry)) return 0;
    auto literal=std::lower_bound(literal_returns.begin(),literal_returns.end(),entry,
        [](const LiteralReturn& item,auto address){return item.entry<address;});
    if(literal!=literal_returns.end() && literal->entry==entry)
        return std::uint64_t(std::int64_t(literal->value));
    const auto tail=std::lower_bound(tail_bindings.begin(),tail_bindings.end(),entry,
                                    [](const TailBinding& b, auto e){return b.entry<e;});
    if(tail!=tail_bindings.end() && tail->entry==entry) {
        const std::uint64_t args[]{self,a1,a2,a3};
        return invoke_recovered(m,tail->target,self,args[tail->a1_from],args[tail->a2_from],a3,services);
    }
    // Fixed source ELF .reginfo gp, not an observed CPU/kernel gp value.
    if (has_screen_task(entry))
        return invoke_screen_task(m,entry,self,a1,services);
    if(has_checkpoint_writer(entry))return checkpoint_writer(m,entry,self,std::uint32_t(a1));
    if (has_manager_op(entry))
        return invoke_manager_ops(m, entry, self, a1, a2, a3, 0x0023daf0);
    if (has_cue_command(entry))
        return invoke_cue_command(m,entry,self,a1,a2,services);
    if (has_record_scope(entry))
        return invoke_record_scope(m,entry,self,a1);
    if (has_name_entry(entry))
        return invoke_name_entry(m,entry,self,a1,services);
    if (has_actor_choice(entry))
        return invoke_actor_choice(m,entry,self,a1,services);
    if (has_timechart_native(entry))
        return invoke_timechart_native(m,entry,self,a1,services);
    if (has_system_menu(entry))
        return invoke_system_menu(m,entry,self,a1,a2,a3,services);
    if (has_media_command(entry))
        return invoke_media_command(m, entry, self, a1, a2, a3, 0x0023daf0,services?services->media:nullptr);
    if (has_control_transfer(entry))
        return invoke_control_transfer(m,entry,self,a1,a2,a3,services);
    if (has_text_command(entry))
        return invoke_text_command(m, entry, self, a1, a2);
    if (has_text_driver(entry))
        return invoke_text_driver(m, entry, self, a1, a2, a3, services, services ? services->text : nullptr);
    if (has_manager_input(entry))
        return invoke_manager_input(m, entry, self, a1, a2, a3, services);
    if (has_page_start(entry))
        return invoke_page_start(m, entry, self, a1, services);
    if (has_page_control(entry))
        return invoke_page_control(m, entry, self, a1, a2, a3, services);
    if (entry >= 0x0010d3d0 && entry <= 0x0010fac8)
        return invoke_script_data(m, entry, self, a1, a2, a3);
    if (entry >= 0x00117d00 && entry <= 0x0011e828)
        return invoke_choice_leaf(m, entry, self, a1);
    std::ostringstream error;
    error << "Unrecovered source function 0x" << std::hex << std::setw(8)
          << std::setfill('0') << entry;
    throw std::runtime_error(error.str());
}
}
