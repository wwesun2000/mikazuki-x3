#include "system_menu.hpp"
#include "control_transfer.hpp"
#include "system_charts.hpp"
#include "timechart_native.hpp"
#include "literal_returns.hpp"
#include "manager_input.hpp"
#include "context_bridges.hpp"
#include "tail_bindings.hpp"
#include "sound_output_mode.hpp"
#include "choice_pipeline.hpp"
#include "guest_memory.hpp"
#include <algorithm>
#include <bit>

namespace kx3 {
namespace {
using u32=std::uint32_t;
using u64=std::uint64_t;
constexpr u32 selector=0x238904, screen=0x2388e8, session=0x2388cc;
constexpr u32 menu_context=0x235f74;
u32 action_table(const GuestMemory& m) { // 1A1D70: retail 175F78(31/32) returns zero.
    const auto mode=m.read_u32(0x235b00);
    return mode==1?0x230428:mode==0||mode==2?0x2303a8:0x230368;
}
u32 count(const GuestMemory& m) {
    const auto n=m.read_u32(action_table(m));
    if(n==0 || n>7)throw std::runtime_error("Invalid original system menu option table");
    return n;
}
void update_tasks(GuestMemory& m,u32 field,u32 value,bool except_group4) {
    const auto tasks=m.read_u32(0x2388bc);
    if(!tasks)throw std::runtime_error("System menu needs original task array 0x002388bc");
    for(u32 i=0;i<37;++i){
        const auto task=tasks+48*i;
        if(m.read_u32(task) && (!except_group4 || m.read_u32(task+8)!=4))m.write_u32(task+field,value);
    }
}
void cue_ui_sound(GuestMemory& m,ExecutionServices* services,u32 id,u32 volume){
    if(!services || !services->system_menu || !services->system_sounds)
        throw std::runtime_error("1B15F0 needs transactional source menu sound output");
    services->system_sounds->push_back(system_sound(m,id,volume,services->system_menu->sounds));
}
void reset_ui_transition(GuestMemory& m){ // 1A1B18
    m.write_u32(0x2388f4,0);m.write_u32(0x2388f0,1);m.write_u32(0x2388fc,0);m.write_u32(0x238900,0);
}
void settings_input(GuestMemory& m,ExecutionServices* services,u32 physical_edges){
    const int point=services && services->choice_input?services->choice_input->menu_index:-1;
    if(!m.read_u32(0x238050) && !m.read_u32(0x1e497e0) && m.read_u32(0x1e41c60) &&
       !(physical_edges&0xe5f0) && point>=0 && point<=4)m.write_u32(0x23891c,u32(point));
    const auto action=run_scenario_return(m,0x1a2a18,0,0,services);
    // 19D2D8..19D318 distinguishes returning to the root from choosing a save slot.
    if(action==UINT64_MAX-1 || action==UINT64_MAX-2){
        run_scenario_return(m,0x1a2738,0,0,services);
        if(action==UINT64_MAX-2)run_scenario_return(m,0x1a8728,0,0,services);
        m.write_u32(screen,action==UINT64_MAX-2?12:0);
    }
}
void leave_modal(GuestMemory& m,u32 manager,ExecutionServices* services,u32 label=0){
    if(m.read_u32(0x2388e4))m.write_u32(0x2388e4,0); // 19D810 -> 19D808
    run_scenario_return(m,0x1a1eb0,0,0,services);
    m.write_u32(0x2062b4,0);m.write_u32(0x2062ac,0); // 135A98
    if(m.read_u32(0x2388dc) && m.read_u32(0x2388d4)){
        m.write_u32(0x2388dc,0); update_tasks(m,40,0,false); // 17A090
    }
    m.write_u32(0x2388d0,0);m.write_u32(0x2388d4,0);m.write_u32(session,0);
    (void)invoke_recovered(m,0x10c8f8,label,0,0,0,services);
}
std::optional<bool> physical_control_available(const GuestMemory& m,u32 manager,u32 helper_offset){
    if(!manager || m.read_u32(0x1e497e0))return false;
    const auto context=m.read_u32(manager+0x40),helper=m.read_u32(manager+helper_offset);
    if(!context || !helper)return false;
    const auto bridge=m.read_u32(m.read_u32(context)+12);
    // 11E860 and its context-specific siblings are the same original virtual
    // bridge with a different helper-table displacement in the second LW.
    const auto forward=std::lower_bound(context_bridges.begin(),context_bridges.end(),bridge,
        [](const auto& item,u32 addr){return item.entry<addr;});
    if(forward==context_bridges.end() || forward->entry!=bridge)return std::nullopt;
    auto method=m.read_u32(m.read_u32(helper)+forward->offset);
    // In particular 134978 (choice) and 134A28 (reading) both jump to
    // 134930 with the same argument registers. Use the ELF-derived aliases.
    const auto tail=std::lower_bound(tail_bindings.begin(),tail_bindings.end(),method,
        [](const auto& fn,u32 addr){return fn.entry<addr;});
    if(tail!=tail_bindings.end() && tail->entry==method && tail->a1_from==1 && tail->a2_from==2)
        method=tail->target;
    if(method>=0x134658 && method<=0x134768 && m.read_u32(method)==0x03e00008 &&
       m.read_u32(method+4)==0x0000102d)return false; // JR RA; DADDU V0,ZERO,ZERO.
    const auto literal=std::lower_bound(literal_returns.begin(),literal_returns.end(),method,
        [](const auto& fn,u32 key){return fn.entry<key;});
    if(literal!=literal_returns.end() && literal->entry==method)return literal->value!=0;
    if(method==0x134708)return false;
    return context_input_predicate(m,manager,method);
}
}
std::optional<bool> system_menu_available(const GuestMemory& m,u32 manager){
    if(!manager || !m.read_u32(manager+0x40) || !m.read_u32(manager+0x284) ||
       m.read_u32(0x1e497e0) || system_menu_view(m,manager).open)return false;
    if(m.read_u32(manager+0x808))return std::nullopt;
    return physical_control_available(m,manager,0x284);
}
std::optional<bool> brightness_control_available(const GuestMemory& m,u32 manager){
    return physical_control_available(m,manager,0x280); // 112D80 -> 1133C0(manager,0).
}
std::optional<bool> inspection_control_available(const GuestMemory& m,u32 manager){
    return physical_control_available(m,manager,0x28c); // 1130E0 -> 112D40 -> 1133C0(manager,3).
}
SystemMenuView system_menu_view(const GuestMemory& m,u32 manager){
    SystemMenuView view;
    if(!manager)return view;
    view.controls_visible=m.read_u32(0x2362d0)!=0; // 141DA8/141DB8/141DC0, GP-0x7820.
    view.brightness_visible=m.read_u32(0x2362c0)!=0; // 141538/141548/141550.
    view.brightness_level=m.read_u32(0x206260);      // 1358F8, selected by 114BB0.
    // 121E68 reads the owner-0 pad. On a triangle edge 121E8C clears the
    // active interval before the context decides whether to open the menu.
    view.can_stop_auto=m.read_u32(manager+0x808)!=0 && !m.read_u32(0x1e497e0);
    const auto notice=m.read_u32(manager+0x838);
    if(m.read_u32(manager+0x834) && notice && m.read_u32(notice+24)==0x189e80){
        const auto payload=m.read_u32(notice+44);
        if(payload){
            const auto variant=m.read_u32(payload);
            // 116180 passes 0 or 1. 189E80 fetches the text descriptors for that variant.
            if(variant>1)throw std::runtime_error("Invalid original 189E80 notice variant");
            const auto table=0x20d798+16*variant;
            if(m.read_u32(table)!=1)throw std::runtime_error("Invalid original 189E80 notice descriptor");
            view.notice_text_address=m.read_u32(m.read_u32(table+4));
        }
    }
    const auto owner=m.read_u32(manager+0x848);
    const auto object=owner?m.read_u32(owner+8):0;
    if(!object || !m.read_u32(owner+4) || !m.read_u32(object+4) || !m.read_u32(session))return view;
    if(object==m.read_u32(manager+0x850) && m.read_u32(object)==0x223c70 && m.read_u32(0x2388e0)){
        view.interval_level=m.read_u32(object+28);
        view.interval_ready=!m.read_u32(object+12) && !m.read_u32(object+16);
        if(view.interval_level<1 || view.interval_level>5)throw std::runtime_error("Invalid 122328 interval");
        view.open=true;view.screen=10;return view;
    }
    if(object!=m.read_u32(manager+0x84c) && object!=m.read_u32(manager+0x854))return view;
    view.open=true;view.focus=m.read_u32(selector);view.screen=m.read_u32(screen);
    if(view.screen==3)view.subfocus=10*m.read_u32(0x2381ac)+m.read_u32(0x2381a8);
    else if(view.screen==2 && m.read_u32(0x238218))view.subfocus=m.read_u32(m.read_u32(0x238218)+4);
    else if(view.screen==4){
        view.subfocus=m.read_u32(0x23891c);
        view.settings_notice=m.read_u32(0x238050)!=0;
        view.settings={m.read_u32(0x23890c),m.read_u32(0x238914),m.read_u32(0x238918),m.read_u32(0x238908)};
    }
    const auto table=action_table(m), n=count(m);
    if(view.focus>=n)throw std::runtime_error("Source system-menu focus outside table");
    for(u32 i=0;i<n;++i){
        const auto id=m.read_u32(table+4+4*i);
        if(id>5)throw std::runtime_error("Unrecovered system menu action");
        view.actions.push_back(SystemMenuAction(id));
    }
    view.can_request_save=(view.screen==0 || view.screen==14) && std::find(view.actions.begin(),view.actions.end(),
        SystemMenuAction::SaveAndQuit)!=view.actions.end();
    return view;
}
void prepare_system_save_resume(GuestMemory& m,u32 manager){
    const auto view=system_menu_view(m,manager);
    if(!view.open || view.screen!=14 || std::find(view.actions.begin(),view.actions.end(),
       SystemMenuAction::SaveAndQuit)==view.actions.end())
        throw std::runtime_error("System save requires the original Save and Quit confirmation screen");
    GuestMemory::Transaction tx(m);
    // Native slot adapter persists the gameplay return produced by the
    // 19D0C0 state-6 / 10C8F8 / 121FC8(0) path.
    m.write_u32(screen,6);
    leave_modal(m,manager,nullptr);
    tx.commit();
}
void complete_auto_save_target(GuestMemory& m,u32 manager,u32 slot,bool resume_story){
    const auto view=system_menu_view(m,manager);
    if(!view.open || view.screen!=12 || slot>=10 || !m.read_u32(0x23890c))
        throw std::runtime_error("Auto-save setup requires original screen 12 and a selected card slot");
    GuestMemory::Transaction tx(m);
    // 1A5DE8 state 18 requests 105538/1057B8(port,slot,1). Both
    // original successful card workers 104038 / 104260 commit these fields.
    m.write_u32(0x239fd8,0);m.write_u32(0x239fdc,slot);m.write_u32(0x239eb4,1);
    m.write_u32(0x239fe8,1);m.write_u32(0x239fec,0);
    m.write_u32(screen,resume_story?6:0);
    if(resume_story)leave_modal(m,manager,nullptr);
    tx.commit();
}
void advance_system_menu(GuestMemory& m,u32 manager,ExecutionServices* s){
    const auto view=system_menu_view(m,manager);
    if(!view.open)return;
    if(!m.read_u32(0x2388d0)){ // 19D0C0 first task update
        reset_ui_transition(m);
        m.write_u32(0x2062b4,1);m.write_u32(0x2062ac,1);
        // 19D0F0..19D108 checks both guest flags independently of the owner type.
        if(m.read_u32(0x2388d8) || m.read_u32(0x2388e0))m.write_u32(screen,10);
        m.write_u32(0x236108,1);m.write_u32(0x236104,m.read_u32(0x23618c));m.write_u32(0x23610c,0);
        m.write_u32(0x2388d0,1);return;
    }
    if(!m.read_u32(0x2388d4)){
        if(m.read_u32(0x236104) || m.read_u32(0x236110)){
            m.write_u32(0x236190,m.read_u32(0x20625c));m.write_u32(0x236100,m.read_u32(0x20625c));return;
        }
        if(!m.read_u32(0x236100) || m.read_u32(0x20625c)!=m.read_u32(0x236100)+1)m.write_u32(0x236100,0);
        m.write_u32(0x2388d4,1);
        if(m.read_u32(0x2388dc))update_tasks(m,40,1,true);
    }
    if(m.read_u32(screen)==10)return; // 19D0C0 has no case 10 input. The owner's 121878 dispatches it.
    if(view.screen>=6 && view.screen<=9){
        u32 label=0;
        if(view.screen==8)label=u32(invoke_timechart_native(m,0x1ae388,0,0,s));
        else if(view.screen==9)label=0x22f9e0;
        else if(view.screen==7){
            const auto i=m.read_u32(0x23821c);
            if(m.read_u32(0x238208) && i<m.read_u32(0x238204)){
                const auto row=m.read_u32(0x1e4bf80+4*i);if(row)label=row+1;
            }
        }
        leave_modal(m,manager,s,label);return;
    }
    const auto edges=m.read_u32(0x1e497e0)?0:choice_device_edges(m,0x1e41c60);
    if(view.screen==16){
        // 19D0C0 case 16. The 1A7C88 dispatcher executes its own indexed
        // state, pad and device checks. 1A1B98 advances its visible fade.
        const auto result=run_scenario_return(m,0x1a8a40,0,0,s);
        if(result){
            reset_ui_transition(m); // 1A1B18; 1A8870 is JR RA / NOP.
            m.write_u32(screen,run_scenario_return(m,0x19cfa8,0,0,s)?0:6);
        }else (void)run_scenario_return(m,0x1a1b98,0,0,s);
        return;
    }
    if(view.screen==4){settings_input(m,s,edges);return;}
    if(view.screen==5 || ((view.screen==12 || view.screen==14) && s && s->choice_input && s->choice_input->original_card_menu)){
        // 19D328 handles the common return of the ordinary and autosave card selectors.
        const auto entry=view.screen==5?0x1a8a00:view.screen==12?0x1a89e0:0x1a8a20;
        const auto result=run_scenario_return(m,entry,0,0,s);
        // 19D0C0 returns -1 to 100A70, which calls 100D30 to end the game loop.
        if(view.screen==14 && result==UINT64_MAX){run_scenario_return(m,0x100d30,0,0,s);return;}
        if(result==1){
            const bool exit=view.screen==14 && run_scenario_return(m,0x19d810,0,0,s) &&
                            !run_scenario_return(m,0x19cfa8,0,0,s);
            m.write_u32(screen,exit?6:0);
        }else (void)run_scenario_return(m,0x1a1b98,0,0,s); // Visible card pass, 19D9E8.
        return;
    }
    if(view.screen==1){
        if(s && s->choice_input && s->choice_input->menu_index>=0 && !m.read_u32(0x2381d8)){
            const auto id=u32(s->choice_input->menu_index),row=id/4,actor=id%4;
            const auto work=m.read_u32(0x2381dc);
            if(work && row<m.read_u32(0x2389a0) && actor<m.read_u32(0x2389a4) &&
               m.read_u32(m.read_u32(0x2381c4)+row*88+actor*20+24)){
                m.write_u32(work+8,actor);m.write_u32(work+12,row);
                const auto first=m.read_u32(work+4);
                if(row<first)m.write_u32(work+4,row);
                else if(row>=first+12)m.write_u32(work+4,row-11);
            }
        }
        const auto outcome=invoke_timechart_native(m,0x1add40,0,0,s);
        if(outcome==1 || outcome==2){
            (void)invoke_timechart_native(m,0x1add08,0,0,s);
            m.write_u32(screen,outcome==1?8:0);
        }
        return;
    }
    if(view.screen==2){ // 19D260..19D298
        const auto action=run_scenario_return(m,0x1af850,0,0,s);
        if(action==1 || action==2){
            run_scenario_return(m,0x1af838,0,0,s);
            m.write_u32(screen,action==1?7:0);
        }
        return;
    }
    if(view.screen==3){ // 19D29C..19D2D4, including the original No.79 replay exception.
        const auto action=run_scenario_return(m,0x1abb48,0,0,s);
        if(action==0 || action==1){
            run_scenario_return(m,0x1ab490,0,0,s);
            m.write_u32(screen,action==1?9:0);
        }
        return;
    }
    if(view.screen!=0){
        // Actual chart jumps and ending replay take their own 19D0C0
        // branches. Returning from these normal screens selects the root.
        if(edges&0x4400){cue_ui_sound(m,s,3,60);m.write_u32(screen,0);}
        return;
    }
    const auto result=run_scenario_return(m,0x1a1c60,0,0,s);
    if(result==UINT64_MAX)return;
    if(result==6){m.write_u32(screen,6);return;}
    if(result>5)throw std::runtime_error("Unexpected 1A1C60 menu result");
    switch(SystemMenuAction(result)){
    case SystemMenuAction::SaveAndQuit:case SystemMenuAction::Memory:
        run_scenario_return(m,0x1a8728,0,0,s);
        m.write_u32(screen,result==3?14:5);return;
    case SystemMenuAction::Endings:
        run_scenario_return(m,0x1ab468,0,0,s);
        m.write_u32(screen,3);return;
    case SystemMenuAction::Settings:run_scenario_return(m,0x1a26a8,0,0,s);m.write_u32(screen,4);return;
    case SystemMenuAction::Timeline:
        (void)invoke_timechart_native(m,0x1adcd0,0,0,s);
        m.write_u32(screen,1);return;
    case SystemMenuAction::Chapters:
        run_scenario_return(m,0x1af818,0,0,s);
        m.write_u32(screen,2);return;
    }
}
void retire_interval_tasks(GuestMemory& m,u32 heap){
    const u32 pool=m.read_u32(0x2388bc);
    if(!pool)return;
    for(u32 i=33;i<37;++i){
        const u32 task=pool+48*i;
        const u32 cleanup=m.read_u32(task+32);
        if(!m.read_u32(task) || !m.read_u32(task+4) || (cleanup!=0x189dd0 && cleanup!=0x18a048))continue;
        // Both original destructors pass task+44 to 17A5F8. Our fixed slot can now be reused.
        if(!heap || m.read_u32(task+8)!=4 || m.read_u32(task+44)!=heap+0x3400+16*(i-33))
            throw std::runtime_error("Invalid 189DD0 interval task payload");
        m.write_u32(task,0);m.write_u32(task+4,0);
    }
}
bool has_system_menu(u32 entry) noexcept{
    switch(entry){
    case 0x132d28: case 0x132db0: case 0x19c9b8: case 0x15de60: case 0x1b0ed0:
    case 0x121648: case 0x1216c8: case 0x121700: case 0x121878: case 0x121900:
    case 0x204a68: case 0x122100: case 0x122108: case 0x122110:
    case 0x121f98: case 0x121fb0: case 0x121fb8: case 0x121fc0: case 0x121fc8: case 0x1225e0:
    case 0x1225b0: case 0x1225c8: case 0x175d68: case 0x17a148:
    case 0x19d5c0: case 0x1ab330: case 0x1ab4a8:
    case 0x1af188: case 0x1af6e0: case 0x1b15f0: return true;
    default:return false;
    }
}
u64 invoke_system_menu(GuestMemory& m,u32 entry,u32 self,u64 a1,u64 a2,u64 a3,ExecutionServices* s){
    auto call=[&](u32 routine,u32 object=0,u64 arg=0){return invoke_recovered(m,routine,object,arg,0,0,s);};
    const auto manager=m.read_u32(0x235e40);
    switch(entry){
    case 0x204a68: // +32 in vtable 223C40. JR RA; DADDU V0,ZERO,ZERO in the delay slot.
        if(m.read_u32(entry)!=0x03e00008 || m.read_u32(entry+4)!=0x0000102d)
            throw std::runtime_error("Unexpected chapter menu predicate");
        return 0;
    case 0x122100:case 0x122108:case 0x122110:
        if(m.read_u32(entry)!=0x03e00008 || m.read_u32(entry+4)!=0)
            throw std::runtime_error("Unexpected chapter menu callback");
        return 0; // void JR RA; NOP
    case 0x15de60:
        return run_scenario_return(m,entry,self,a1,s);
    case 0x1b0ed0:enqueue_sound_output_mode(m,self);return 0;
    case 0x132d28:case 0x132db0:{ // Original 92-byte slot methods are identical.
        const auto script=m.read_u32(manager+0x38);
        const auto operand=call(0x10d5d8,script,1);
        (void)call(0x19c9b8,u32(call(0x10d750,script)),operand);return 0;
    }
    case 0x19c9b8:{
        const auto target=m.read_u32(0x1e4ab70);
        if(target)(void)invoke_recovered(m,target,self,a1,a2,a3,s);
        return 0;
    }
    case 0x1ab330:return consume_source_ending_list(m);
    case 0x1ab4a8:return mark_source_ending(m,self);
    case 0x1af188:update_chapter_progress(m,self,a1);return 0;
    case 0x1af6e0:prepare_chapter_menu(m);return 0;
    case 0x121648:{
        auto value=m.read_u32(menu_context);
        if(!value){
            if(!s || !s->system_menu || !(value=s->system_menu->context_storage) || (value&3))
                throw std::runtime_error("121648 requires reserved guest space for 1215F8");
            m.write_u32(value,0x223b90);m.write_u32(menu_context,value);
        }
        return value;
    }
    case 0x121700:{
        const auto predicate=u32(a1);
        return call(m.read_u32(m.read_u32(predicate)+112),predicate,self);
    }
    case 0x1216c8:(void)call(0x1225e0,m.read_u32(u32(a1)+0x848));return 1;
    case 0x1225e0:if(m.read_u32(self+4))(void)call(0x121878,m.read_u32(self+8));return 0;
    case 0x121878:{
        if(!m.read_u32(self+4))return 0;
        const auto old=m.read_u32(self+12);
        m.write_u32(self+12,std::bit_cast<std::int32_t>(old-1)<0?0:old-1);
        if(m.read_u32(self+16)){
            // 1219E0 asks 175E70(6,0), otherwise goes through the
            // normal 15FDE0 owner-0 input gate.
            const auto input_owner=m.read_u32(0x1e497e0);
            const auto masked=input_owner!=0 && input_owner!=6;
            if(masked || !m.read_u16(0x1e41c60+8))m.write_u32(self+16,0);
            if(m.read_u32(self+16))return 0;
        }
        if(!m.read_u32(self+12))(void)call(m.read_u32(m.read_u32(self)+24),self);
        return 0;
    }
    case 0x121f98:return call(0x19d5c0);
    case 0x121fb0:case 0x121fb8:case 0x121fc0:return 0; // Original JR RA; NOP.
    case 0x19d5c0:{
        run_scenario_return(m,0x1a1eb0,0,0,s);
        m.write_u32(session,1);m.write_u32(0x2388dc,1);
        const auto mode=m.read_u32(0x235b00);
        if(mode==1)(void)invoke_timechart_native(m,0x1adbd8,0,0,s);
        if(mode==0 || mode==2)prepare_chapter_menu(m);
        m.write_u32(screen,0);
        return 0;
    }
    case 0x175d68:{
        const auto addr=0x1e497bc+4*self;
        if(!m.read_u32(addr))return 0;
        m.write_u32(addr,0);return 1;
    }
    case 0x17a148:update_tasks(m,36,0,false);return 0;
    case 0x1225b0:m.write_u32(self+8,u32(a1));m.write_u32(self+4,1);return 1;
    case 0x1225c8:m.write_u32(self+8,0);m.write_u32(self+4,0);return 1;
    case 0x121fc8:
        (void)call(0x121900,self);
        if(a1)(void)call(0x1125c8,manager,a1);
        return 0;
    case 0x121900:
        m.write_u32(self+4,0);(void)call(0x112e48,manager);(void)call(0x17a148);
        (void)call(m.read_u32(m.read_u32(self)+20),self);(void)call(0x175d68,6);
        (void)call(0x1114f0,manager,m.read_u32(self+8));
        (void)call(m.read_u32(m.read_u32(self)+28),self);
        return call(0x1225c8,m.read_u32(manager+0x848),self);
    case 0x1b15f0:
        if(!self || self>7 || a2 || a3)throw std::runtime_error("Unrecovered direct 1B15F0 non-menu sound");
        cue_ui_sound(m,s,self,u32(a1));return 0;
    default:throw std::invalid_argument("Unknown system menu source routine");
    }
}
}
