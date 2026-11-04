#include "control_transfer.hpp"
#include "ee_scalar.hpp"
#include "guest_memory.hpp"
#include "recovered.hpp"
#include "choice_pipeline.hpp"
#include "timechart_native.hpp"
#include "sound_output_mode.hpp"
#include "card_volume.hpp"
#include "chapter_card_worker.hpp"
#include "staff_roll.hpp"
#include "cue_effect.hpp"
#include "sab_animation.hpp"
#include "mystery_panel.hpp"
#include "text_driver.hpp"
#include "story_frame.hpp"
#include "media_active.hpp"
#include "name_entry.hpp"
#include <atomic>
#include <chrono>
#include <sstream>
#include <cstring>
#include <optional>

namespace kx3 {
namespace {
using namespace ee;
constexpr u32 stack_base=0x70000000, stack_top=stack_base+16384, done=0x3ff000;
struct PS2Runtime {
    GuestMemory& m;
    ExecutionServices* services;
    std::array<std::uint8_t,stack_top-stack_base> stack{};
    unsigned branches=4096;
    bool vm_context=false;
    u32 card_thread=0;
    u32 waiting=0;
    std::vector<u32> frames;
    u32 credit_line=0,credit_width=0,credit_cursor=0;
    TextGlyphRequest primary_glyph{},ruby_glyph{};
    std::vector<TextGlyphEvent> glyphs;
    TextGlyphEvent* drawing_glyph=nullptr;
    Quad load_quad(u32 address){
        address&=~15u; // EE LQ aligns the guest address down.
        return {load(address,8),load(address+8,8)};
    }
    void store_quad(u32 address,Quad q){address&=~15u;store(address,q.lo,8);store(address+8,q.hi,8);}
    bool eeCheckpointAt(u32 pc){
        if(!branches--){std::ostringstream e;e<<"EE branch budget exhausted at 0x"<<std::hex<<pc;throw std::runtime_error(e.str());}
        return false;
    }
    [[noreturn]] void handleBreak(std::uint8_t*,const R5900Context* c){
        std::ostringstream error;error<<"Original EE BREAK at 0x"<<std::hex<<c->pc;throw std::runtime_error(error.str());
    }
    u64 load(u32 p,unsigned width){
        if(p>=stack_base && p<=stack_top-width){
            u64 value=0;for(unsigned i=0;i<width;++i)value|=u64(stack[p-stack_base+i])<<(8*i);
            return value;
        }
        if(width==1)return m.read_u8(p);
        if(width==2)return m.read_u16(p);
        if(width==8)return u64(m.read_u32(p)) | (u64(m.read_u32(p+4))<<32);
        if(width!=4)throw std::runtime_error("Unexpected scenario-return LD outside stack");
        return m.read_u32(p);
    }
    void store(u32 p,u64 value,unsigned width){
        // 14DDD4 increments the row width before 14DDE0 advances its nibble cursor.
        if(credit_width && p==credit_width && !credit_cursor && width==4 && u32(value)>m.read_u32(p))
            credit_cursor=m.read_u32(credits::live_cursor);
        if(p>=stack_base && p<=stack_top-width){
            for(unsigned i=0;i<width;++i)stack[p-stack_base+i]=std::uint8_t(value>>(8*i));
        }else{
            if(width==1)m.write_u8(p,std::uint8_t(value));
            else if(width==2)m.write_u16(p,std::uint16_t(value));
            else if(width==4)m.write_u32(p,u32(value));
            else if(width==8){m.write_u32(p,u32(value));m.write_u32(p+4,u32(value>>32));}
            else throw std::runtime_error("Unexpected scenario-return SD outside stack");
        }
    }
    enum class GuestBranchKind {DirectCall,DirectJump,IndirectCall,IndirectJump,Return};
    std::string cstring(u32 address){
        std::string s;
        for(unsigned i=0;i<256;++i){
            const auto ch=char(load(address+i,1));
            if(!ch)return s;
            s+=ch;
        }
        throw std::runtime_error("Unterminated card path");
    }
    void string_to(u32 address,const std::string& s){
        for(unsigned i=0;i<s.size();++i)store(address+i,std::uint8_t(s[i]),1);
        store(address+u32(s.size()),0,1);
    }
    bool card_call(u32 target,R5900Context& c);
    u32 signal() const{return card_thread==0x103640?0x1353000:0x1353004;}
    bool acquire_card_lock(u32 lock){
        if(lock!=0x204bc0 && lock!=0x204be0)throw std::runtime_error("Unbound card thread mutex");
        if(m.read_u32(lock+4)!=UINT32_MAX)return false;
        const u32 priority=m.read_u32(card_thread==0x103640?0x1357c00:0x1357c04),ceiling=m.read_u32(lock+12);
        m.write_u32(lock+4,card_thread==0x103640?2:3);
        m.write_u32(lock+8,ceiling && ceiling<priority?priority:0);return true;
    }
    bool dispatchGuestBranch(std::uint8_t*,R5900Context*,u32,u32,u32,GuestBranchKind,const char*);
};
#define READ32(p) u32(runtime->load(p,4))
#define READ16(p) std::uint16_t(runtime->load(p,2))
#define READ64(p) runtime->load(p,8)
#define WRITE8(p,v) runtime->store(p,v,1)
#define WRITE16(p,v) runtime->store(p,v,2)
#define WRITE32(p,v) runtime->store(p,v,4)
#define WRITE64(p,v) runtime->store(p,v,8)
#define eeCheckpointDue() eeCheckpointAt(ctx->pc)
#include "scenario_return_generated.hpp"
#define GPR_S32(c,n) std::bit_cast<i32>((c)->word(n))
#define GPR_S64(c,n) std::bit_cast<std::int64_t>((c)->r[n].lo)
#define SLL32(v,s) (u32(v)<<((s)&31))
#define SRL32(v,s) (u32(v)>>((s)&31))
#define SRA32(v,s) (std::bit_cast<i32>(u32(v))>>((s)&31))
#define SUB32(a,b) (u32(a)-u32(b))
#define SET_GPR_ZE32(c,n,v) (c)->set64(n,u32(v))
#define READ8(p) std::uint8_t(runtime->load(p,1))
#define FAST_READ32(p) READ32(p)
#define FAST_READ64(p) READ64(p)
#define FAST_READ8(p) READ8(p)
#define FAST_WRITE32(p,v) WRITE32(p,v)
#define READ128(p) runtime->load_quad(p)
#define WRITE128(p,v) runtime->store_quad(p,v)
template<class Lane> Quad subtract_lanes(Quad left,Quad right){
    using Lanes=std::array<Lane,sizeof(Quad)/sizeof(Lane)>;
    auto result=std::bit_cast<Lanes>(left);
    const auto other=std::bit_cast<Lanes>(right);
    for(std::size_t i=0;i<result.size();++i)result[i]=Lane(result[i]-other[i]);
    return std::bit_cast<Quad>(result);
}
inline Quad PS2_PSUBB(Quad a,Quad b){return subtract_lanes<std::uint8_t>(a,b);}
inline Quad PS2_PSUBW(Quad a,Quad b){return subtract_lanes<u32>(a,b);}
inline Quad PS2_PAND(Quad a,Quad b){return {a.lo&b.lo,a.hi&b.hi};}
inline Quad PS2_POR(Quad a,Quad b){return {a.lo|b.lo,a.hi|b.hi};}
inline Quad PS2_PXOR(Quad a,Quad b){return {a.lo^b.lo,a.hi^b.hi};}
inline Quad PS2_PNOR(Quad a,Quad b){return {~(a.lo|b.lo),~(a.hi|b.hi)};}
inline Quad PS2_PCPYLD(Quad rs,Quad rt){return {rt.lo,rs.lo};}
inline Quad unpack_high(Quad a,Quad b){return {a.hi,b.hi};}
#define _mm_unpackhi_epi64(a,b) unpack_high(a,b)
// Matches the pinned ps2xRuntime ps2_runtime.h hook. It has no observable
// effect; the following FAST_WRITE32 performs the journaled guest store.
inline void ps2TraceGuestWrite(std::uint8_t*,u32,u32,u64,u64,const char*,const R5900Context*) noexcept {}
#define FPU_C_OLE_S(a,b) (ordinary(a)<=ordinary(b))
#define KX3_MENU_ENTRY(address,fn) void fn(std::uint8_t*,R5900Context*,PS2Runtime*);
#include "return_menu_entries.hpp"
#include "interval_menu_entries.hpp"
#include "card_services_entries.hpp"
#include "card_resume_entries.hpp"
#include "staff_roll_entries.hpp"
#include "ending_vm_entries.hpp"
#include "ending_menu_entries.hpp"
#include "settings_menu_entries.hpp"
#include "root_menu_entries.hpp"
#include "system_card_entries.hpp"
#include "title_picker_entries.hpp"
#include "vm_context_entries.hpp"
#include "scenario_branches_entries.hpp"
#include "scenario_text_entries.hpp"
#include "scenario_history_entries.hpp"
#include "scenario_input_entries.hpp"
#include "story_glyphs_entries.hpp"
#include "story_contexts_entries.hpp"
#include "choice_preview_entries.hpp"
#include "readback_handlers_entries.hpp"
#include "answer_input_entries.hpp"
#include "chart_progress_entries.hpp"
#include "scene_cue_entries.hpp"
#include "mystery_panels_entries.hpp"
#undef KX3_MENU_ENTRY
#include "return_menu_generated.hpp"
#include "interval_menu_generated.hpp"
#include "card_services_generated.hpp"
#include "card_resume_generated.hpp"
using __m128i=Quad;
inline std::uint16_t _mm_extract_epi16(Quad q,unsigned index){
    return std::bit_cast<std::array<std::uint16_t,8>>(q).at(index);
}
inline Quad _mm_set_epi16(std::uint16_t h7,std::uint16_t h6,std::uint16_t h5,std::uint16_t h4,
                          std::uint16_t h3,std::uint16_t h2,std::uint16_t h1,std::uint16_t h0){
    return std::bit_cast<Quad>(std::array<std::uint16_t,8>{h0,h1,h2,h3,h4,h5,h6,h7});
}
#define SET_GPR_S64(c,n,v) (c)->set64(n,u64(v))
inline u64 Ps2HiLoToU64(u64 hi,u64 lo){return (hi<<32)|u32(lo);}
inline u64 Ps2SignExt32ToU64(u32 v){return u64(std::int64_t(std::bit_cast<i32>(v)));}
// PMFHL.LW takes words 0 and 2 from each 128-bit LO/HI accumulator.
#define PS2_PMFHL_LW(hi,lo) (Quad{Ps2HiLoToU64((hi),(lo)),Ps2HiLoToU64(ctx->hi1,ctx->lo1)})
#include "staff_roll_generated.hpp"
#include "ending_vm_generated.hpp"
#include "ending_menu_generated.hpp"
#include "settings_menu_generated.hpp"
#include "root_menu_generated.hpp"
#include "system_card_generated.hpp"
#include "title_picker_generated.hpp"
#include "vm_context_generated.hpp"
#include "scenario_branches_generated.hpp"
#include "scenario_text_generated.hpp"
#include "scenario_history_generated.hpp"
#include "scenario_input_generated.hpp"
#define FPU_MUL_S(a,b) round_towards_zero(double(a)*double(b))
#include "story_glyphs_generated.hpp"
#define FPU_CVT_W_S(a) static_cast<i32>(std::clamp(double(ordinary(a)),double(INT32_MIN),double(INT32_MAX)))
#define FPU_NEG_S(a) (-ordinary(a))
#include "story_contexts_generated.hpp"
#include "choice_preview_generated.hpp"
#include "readback_handlers_generated.hpp"
#include "answer_input_generated.hpp"
#include "chart_progress_generated.hpp"
#undef FPU_NEG_S
#undef FPU_CVT_W_S
#undef FPU_MUL_S
#include "scene_cue_generated.hpp"
#include "mystery_panels_generated.hpp"
#undef eeCheckpointDue
#undef PS2_PMFHL_LW
#undef SET_GPR_S64
#undef _mm_unpackhi_epi64
using Body=void(*)(std::uint8_t*,R5900Context*,PS2Runtime*);
#include "card_io_bindings.hpp"
#include "staff_roll_bindings.hpp"
Body menu_body(u32 address){
    switch(address){
    case 0x122070:return FUN_00122070_0x122070;
    case 0x10d260:return FUN_0010d260_0x10d260;
    case 0x1218f8:return FUN_001218f8_0x1218f8;
    case 0x114b28:return FUN_00114b28_0x114b28;
    case 0x133f60:return FUN_00133f60_0x133f60;
#define KX3_MENU_ENTRY(address,fn) case address:return fn;
#include "return_menu_entries.hpp"
#include "interval_menu_entries.hpp"
#include "card_services_entries.hpp"
#include "card_resume_entries.hpp"
#include "staff_roll_entries.hpp"
#include "ending_vm_entries.hpp"
#include "ending_menu_entries.hpp"
#include "settings_menu_entries.hpp"
#include "root_menu_entries.hpp"
#include "system_card_entries.hpp"
#include "title_picker_entries.hpp"
#include "vm_context_entries.hpp"
#include "scenario_branches_entries.hpp"
#include "scenario_text_entries.hpp"
#include "scenario_history_entries.hpp"
#include "scenario_input_entries.hpp"
#include "story_glyphs_entries.hpp"
#include "story_contexts_entries.hpp"
#include "choice_preview_entries.hpp"
#include "readback_handlers_entries.hpp"
#include "answer_input_entries.hpp"
#include "chart_progress_entries.hpp"
#include "scene_cue_entries.hpp"
#include "mystery_panels_entries.hpp"
#undef KX3_MENU_ENTRY
    default:return nullptr;
    }
}
bool PS2Runtime::dispatchGuestBranch(std::uint8_t* ram,R5900Context* c,u32 target,u32 pc,u32 resume,GuestBranchKind kind,const char*){
    if(c->in_delay_slot || c->pc!=target)throw std::runtime_error("Scenario return before original delay slot");
    if(kind==GuestBranchKind::Return)return false;
    const bool call=kind==GuestBranchKind::DirectCall || kind==GuestBranchKind::IndirectCall;
    if(call && c->word(31)!=pc+8)throw std::runtime_error("Scenario call link mismatch");
    const auto ra=c->word(31);
    if(target==0x170658 && services && services->title_buttons && (pc==0x108d74 || pc==0x10a01c)){
        // The focused title window owns this pad read. Keep the actual game's
        // movement, confirmation, action lookup, cancel priority and sounds.
        const auto owner=pc==0x108d74?0x23a138u:0x23a258u;
        if(c->word(4)!=owner)throw std::runtime_error("Invalid title window pad owner");
        store(c->word(5),*services->title_buttons,2);c->set32(2,1);c->pc=ra;return call;
    }
    // Readback reaches the ELF body of 135660 directly. It has already moved
    // the guest descriptor before tail-calling 138B30. Bind its prepared ISO
    // assets in the same transaction, then continue through the original tail.
    if(pc==0x1356f4 && target==0x138b30 && services && services->media)
        services->media->adopt_completed_scene(m);
    if(target==0x195a80){
        // 195A80 -> 1959F0 queries the decoder while the EE caller's
        // temporary kernel priority is raised. Host scene updates execute
        // serially; the source work object and its published mutex remain
        // guest-visible. A missing decoder is original status 5 (195A7C).
        const u32 decoder=m.read_u32(0x237e78);
        u32 status=5;
        if(decoder){
            (void)invoke_recovered(m,0x1536a8,decoder+0x440,0,0,0,services);
            (void)invoke_recovered(m,0x153a70,decoder+0x440,0,0,0,services);
            status=m.read_u32(decoder+0x4b4);
        }
        c->set32(2,status);c->pc=ra;return call;
    }
    if((pc==0x19c884 || pc==0x19c92c || pc==0x19cb6c) && !menu_body(target) &&
       services && services->choice && services->choice->supports_source(target)){
        const std::array<u64,2> args{c->r[4].lo,c->r[5].lo};
        c->set64(2,services->choice->call_source(m,target,std::span(args).first(pc==0x19cb6c?1:2)));
        c->pc=ra;return call;
    }
    if(target==0x145958 && services && services->iso_files){
        c->set32(2,services->iso_files->source_file_size(cstring(c->word(4))));
        c->pc=ra;return call;
    }
    if(target==0x1d2ee4 && pc==0x1b15cc && services && services->iso_files){
        // 1B1598 supplies a %06d SE bank key. 1D3858 rejects absent or
        // flagged-out entries; 1D2EE4 then reads bit 4 of the record flags.
        const auto key=cstring(c->word(4));
        u32 id=0;
        bool numeric=key.size()==6;
        for(char ch:key){
            if(ch<'0' || ch>'9'){numeric=false;break;}
            id=id*10+u32(ch-'0');
        }
        c->set32(2,numeric && services->iso_files->sound_retention_flag(id));
        c->pc=ra;return call;
    }
    // Retain the native hit testing of the ordinary name editor. Answer
    // editors selected by 11A718 own different vtables and run the ELF body.
    if(target==0x11ac10 && c->word(4)==m.read_u32(0x235ed0)){
        c->set64(2,invoke_name_entry(m,target,c->word(4),0,services));c->pc=ra;return call;
    }
    if(target==0x17a560 && (pc==0x18981c || pc==0x189e54)){
        const bool selector=pc==0x18981c;
        const u32 task=c->word(selector?17:16), first=m.read_u32(0x2388bc)+33*48;
        if(!services || !services->screen_task_heap || task<first || task>=first+4*48 || (task-first)%48 ||
           m.read_u32(task+8)!=4 || c->word(4)!=(selector?16u:4u) || c->word(5)!=(selector?0x22f150u:0x22f170u) ||
           c->word(6)!=(selector?219u:125u) || c->word(7) || c->word(8)!=13)
            throw std::runtime_error("Unexpected 1897B8/189DE8 interval widget allocation");
        // Four mode-4 task slots, each with a reusable 16-byte private payload.
        c->set32(2,services->screen_task_heap+0x3400+16*((task-first)/48));c->pc=ra;return call;
    }
    if(target==0x17a1a8 && pc==0x17a0b4){
        m.write_u32(c->word(4)+40,0);c->pc=ra;return call;
    }
    if(target==0x17a560 && (pc==0x184d70 || pc==0x185a38)){
        const bool bank=pc==0x184d70;
        if(c->word(4)!=(bank?0x144u:0x30u) || c->word(5)!=(bank?0x22eef0u:0x22ef10u) ||
           c->word(6)!=(bank?0x1b4u:0x45u) || c->word(7) || c->word(8)!=13)
            throw std::runtime_error("Unexpected original name task allocation ABI");
        c->set32(2,name_task_payload(m,c->word(bank?17:16),c->word(4)));c->pc=ra;return call;
    }
    auto* frame=services?services->manager_frame:nullptr;
    if(frame && pc==0x11320c)frame->finish(m,m.read_u32(0x235e40),*services);
    if(frame && (pc==0x1131fc || pc==0x113250) && ++frame->result.script_steps>65536)
        throw std::runtime_error("113148 inner-loop step budget exceeded");
    // Capture the two actual text reads in 1126E0. Speculative reads by its
    // lookahead loop never create display events.
    if((pc==0x112794 && target==0x10d5d8) || (pc==0x112b2c && target==0x10d6c8)){
        const bool ruby=pc==0x112b2c;
        const u32 script=c->word(4),manager=c->word(18);
        const u32 address=m.read_u32(script+(ruby?0xdc:0xd8));
        const auto raw=std::uint16_t((u32(m.read_u8(address))<<8)|m.read_u8(address+1));
        auto& request=ruby?ruby_glyph:primary_glyph;
        request={ruby?0x16b608u:0x16b498u,manager,m.read_u32(manager+0x3c),address,raw,0,ruby};
        if(!ruby && m.read_u32(script+0xd0)==43 && m.read_u32(manager+0x40)==m.read_u32(0x235f40)){
            const auto caller=m.read_u32(manager+0x2c4),after=m.read_u32(manager+0x2c8);
            if(caller<32 && after){
                const auto block=m.read_u32(script+8+caller*4);
                if(block){
                    const auto site=m.read_u32(block+0x430)+after-1;
                    if(site<GuestMemory::size && m.read_u8(site)==0x0e)request.insertion_site=site;
                }
            }
        }
    }
    if((pc==0x112a34 && target==0x16b498) || (pc==0x112b54 && target==0x16b608)){
        auto& request=pc==0x112a34?primary_glyph:ruby_glyph;
        if(drawing_glyph || request.source_entry!=target || request.font!=c->word(4))
            throw std::runtime_error("Original font insertion lost its script source");
        request.display_unit=std::uint16_t(c->word(5));
        const auto channel=m.read_u32(request.font+(request.ruby?12:8)),pool=m.read_u32(channel);
        const auto count=m.read_u32(pool+4),format=m.read_u32(channel+4);
        TextGlyphEvent event{request,0,0,m.read_u32(channel+28),int(m.read_u32(format+4)),
                             int(m.read_u32(format+8)),m.read_u32(format+12),m.read_u32(format+12)};
        drawing_glyph=&event;
        menu_body(target)(ram,c,this);
        drawing_glyph=nullptr;
        if(c->pc!=ra)throw std::runtime_error("Original glyph call failed to return");
        const auto after=m.read_u32(pool+4);
        if(after==count+1 && after<m.read_u32(pool)){
            const auto node=m.read_u32(pool+8)+56*count;
            event.node_address=node;
            event.x=int(m.read_u32(node+12));event.y=int(m.read_u32(node+16));
            event.width=m.read_u32(node+20)-m.read_u32(node+12);
            event.height=m.read_u32(node+24)-m.read_u32(node+16);
            if(event.resource_atlas>=0)event.atlas_address=0;
            else if(!event.metric_record)throw std::runtime_error("Glyph node without original FNT record");
        }else if(after!=count || request.display_unit!=0x8140)
            throw std::runtime_error("Unexpected original glyph pool update at 169C70");
        glyphs.push_back(event);return true;
    }
    if(drawing_glyph && target==0x168dd0)drawing_glyph->metric_record=c->word(5);
    if(drawing_glyph && target==0x169218)drawing_glyph->resource_atlas=4;
    if(drawing_glyph && target==0x169a48 && c->word(5)==0x8140){
        const auto format=m.read_u32(c->word(4)+4);
        drawing_glyph->x=int(m.read_u32(format+4));drawing_glyph->y=int(m.read_u32(format+8));
        drawing_glyph->width=m.read_u32(format+12);
    }
    if(card_thread && target==0x1b52a0 && (pc==0x103cb4 || pc==0x103664)){
        if(!m.read_u32(signal())){waiting=2;c->pc=resume;return false;}
        m.write_u32(signal(),0);c->set32(2,0);c->pc=resume;return true;
    }
    if(card_thread && target==0x14f0f0){
        waiting=1;c->pc=resume;return false;
    }
    if(card_thread && target==0x1536a8){
        if(!acquire_card_lock(c->word(4))){waiting=3;c->pc=resume;return false;}
        c->pc=ra;return true;
    }
    if(card_thread && target==0x153a70){
        const auto lock=c->word(4);
        if((lock!=0x204bc0 && lock!=0x204be0) || m.read_u32(lock+4)!=(card_thread==0x103640?2u:3u))
            throw std::runtime_error("Unowned card thread mutex release");
        m.write_u32(lock+4,UINT32_MAX);m.write_u32(lock+8,0);c->pc=ra;return true;
    }
    if(const auto body=menu_body(target)){
        // 11E4E8 tail-calls the original choice navigation method. Mouse
        // targeting supplies its normal directional samples until the clicked
        // cell is focused; the original code invokes every intermediate
        // notification, moves the pointer and recolors the source nodes.
        const bool choice_site=pc==0x11e76c || pc==0x118d54 || pc==0x11e780;
        const auto* input=choice_site && services?services->choice_input:nullptr;
        const u32 choice=input && (input->mouse_index>=0 || input->mouse_confirm)?
            m.read_u32(m.read_u32(0x235e40)+8):0;
        const bool redirected=input && input->mouse_index>=0 && choice &&
            !m.read_u32(choice+0x194) && !m.read_u32(m.read_u32(0x235e40)+0x808) &&
            u32(input->mouse_index)<m.read_u32(choice+4) && m.read_u32(choice+4)<=10;
        if(pc==0x11e76c && target==0x11e4e8 && redirected){
            // The generated J at 11E500 calls 118BF8 directly. Repeat the
            // original wrapper at its JAL boundary, including its delay slot
            // and manager lookup, once per required directional sample.
            const auto focus=u32(input->mouse_index),count=m.read_u32(choice+4);
            const auto self=c->r[4].lo,owner=c->r[5].lo;
            for(u32 n=0;n<count;++n){
                const auto before=m.read_u32(choice+0x168);
                c->pc=target;c->set64(4,self);c->set64(5,owner);body(ram,c,this);
                if(c->pc!=ra)throw std::runtime_error("11E4E8 did not return to original choice caller");
                const auto after=m.read_u32(choice+0x168);
                if(after==focus || before==after)break;
            }
            return true;
        }
        const u32 edge_output=target==0x15fe30?c->word(4):0;
        const bool panel_draw=(pc>=0x14a280 && pc<0x14b020) || (pc>=0x14be48 && pc<0x14cb80);
        const u32 sprite=panel_draw && target==0x135cf8?c->word(4):0;
        // 14A768 increments s1 after drawing each culprit cell. 14C4D8
        // saves the memory cell ordinal before calling the same GS helper.
        const u32 option=pc==0x14a75c?c->word(17):pc==0x14c4e8?c->word(3):UINT32_MAX;
        if(panel_draw && target==0x1363c8)mystery::bind_texture(m,c->word(5),c->word(7),c->word(9),c->word(10));
        if(target==0x136f10 && pc==0x14d8fc)credit_line=c->word(4);
        const bool draw_credit=target==0x14dba8 && pc==0x14db68;
        u32 slot=14;bool continued=false,align=true;
        if(draw_credit){
            if(credit_line<credits::copy || credit_line>=credits::copy+m.read_u32(credits::file_size))
                throw std::runtime_error("14DB68 lacks the original staff line read");
            const auto raw=m.bytes(credit_line,credits::copy+m.read_u32(credits::file_size)-credit_line);
            const auto end=std::find_if(raw.begin(),raw.end(),[](auto ch){return !ch || ch=='\r' || ch=='\n';});
            if(cstring(c->word(4))!=std::string(raw.begin(),end))throw std::runtime_error("14DB68 staff temporary differs from source line");
            continued=m.read_u32(0x23683c)!=0;
            align=!continued || m.read_u32(0x236834);
            if(continued)slot=m.read_u32(0x236874);
            else for(slot=0;slot<14 && m.read_u32(credits::first_row+slot*20);++slot){}
            credit_width=slot<14?credits::first_row+slot*20+12:0;credit_cursor=0;
        }
        if(target==0x104998){
            // The 1020D8 platform bootstrap reserves DE4 bytes for the card
            // directory object, then creates/releases the priority-19 lock.
            // Older checkpoints predate this service; bind only absent state.
            if(!m.read_u32(0x235b6c))m.write_u32(0x235b6c,0x1352000);
            if(m.read_u32(0x204bc0)==UINT32_MAX){
                m.write_u32(0x204bc0,8);m.write_u32(0x204bc4,UINT32_MAX);
                m.write_u32(0x204bc8,0);m.write_u32(0x204bcc,19);
            }
        }
        if(card_thread)frames.push_back(target);
        body(ram,c,this);
        if(edge_output && services && services->choice_input && (pc==0x1abb70 || pc==0x1af86c) &&
           !m.read_u32(0x1e497e0) && m.read_u32(0x1e41c60)){
            // Each caller read the direction repeat mask into SP+0, then
            // the new pad edges into SP+2. Keep its own direction/cancel priority.
            const bool ending=pc==0x1abb70;
            const u32 edges=u32(load(edge_output,2));
            const auto& pointer=*services->choice_input;
            const u32 selected=u32(pointer.menu_index);
            const u32 work=ending?0:m.read_u32(0x238218);
            const u32 count=ending?m.read_u32(0x2381a0):m.read_u32(work+8);
            if(pointer.menu_index>=0 && selected<count && !(load(edge_output-2,2)&(ending?0xf0:0x8050)) &&
               !(edges&0x6500)){
                if(ending){
                    m.write_u32(0x2381a8,selected%10);m.write_u32(0x2381ac,selected/10);
                }else m.write_u32(work+4,selected);
                if(pointer.menu_confirm)store(edge_output,edges|0x2000,2);
            }
        }
        if(edge_output && pc==0x1a1ee0 && services && services->choice_input &&
           !m.read_u32(0x1e497e0) && m.read_u32(0x1e41c60)){
            const auto& pointer=*services->choice_input;
            const u32 edges=u32(load(edge_output,2));
            // S0 holds the action table actually returned by the retail 1A1D70.
            if(pointer.menu_index>=0 && u32(pointer.menu_index)<m.read_u32(c->word(16)) &&
               !(edges&0xe550)){
                m.write_u32(0x238904,u32(pointer.menu_index));
                if(pointer.menu_confirm)store(edge_output,edges|0x2000,2);
            }
        }
        if(edge_output && pc==0x1a2a34 && services && services->choice_input &&
           services->choice_input->menu_confirm && !m.read_u32(0x1e497e0) && m.read_u32(0x1e41c60)){
            const auto row=services->choice_input->menu_index;
            const bool notice=m.read_u32(0x238050)!=0;
            const auto edges=u32(load(edge_output,2));
            if(!(edges&0xe5f0) && (notice?row==0x10000:row>=0 && row<5))
                store(edge_output,edges|(notice || row==4?0x2000:0x20),2);
        }
        if(edge_output && input && !m.read_u32(0x1e497e0) && m.read_u32(0x1e41c60)){
            if(pc==0x118d54 && redirected){
                const auto focus=m.read_u32(choice+0x168),wanted=u32(input->mouse_index);
                const auto keys=std::uint16_t(m.read_u16(edge_output)&~0x8050u);
                m.write_u16(edge_output,keys | (wanted>focus?0x40:wanted<focus?0x10:0));
            }
            if(pc==0x11e780 && input->mouse_confirm &&
               (input->mouse_index<0 || (redirected && m.read_u32(choice+0x168)==u32(input->mouse_index))))
                m.write_u16(edge_output,m.read_u16(edge_output)|0x2000);
        }
        if(target==0x1126e0 && !glyphs.empty()){
            if(services && services->text)services->text->stage_glyph_events(glyphs);
            glyphs.clear();
        }
        if(sprite)mystery::remember_sprite(m,sprite,option);
        if(draw_credit){
            if(slot<14 && m.read_u32(credits::first_row+slot*20))
                credits::remember_line(m,slot,credit_line-credits::copy,credit_cursor?credit_cursor:m.read_u32(credits::live_cursor),continued,align);
            credit_width=0;
        }
        if(waiting)return false;
        if(card_thread)frames.pop_back();
    }else if(mystery::active(m) && (target==0x1453a8 || target==0x145590 || target==0x1456f8 || target==0x145980) &&
             ((pc>=0x149ed0 && pc<0x14ce00) || pc==0x14539c)){
        c->set32(2,mystery::file_service(m,services,target,c->word(4),c->word(5),c->word(6),c->word(7)));c->pc=ra;
    }else if(staff_device_call(*this,target,pc,*c) || card_call(target,*c)){
        c->pc=ra;
    }else switch(target){
    case 0x16b8a0:
        if(pc!=0x10c9ec)throw std::runtime_error("Unknown glyph fade calling convention");
        c->set64(2,invoke_recovered(m,target,std::bit_cast<u32>(c->f[12]),c->word(4),0,0,services));
        c->pc=ra;break;
    case 0x1b5190:{
        // WakeupThread after publishing a sound ring. The native worker
        // consumes the same ring at the next committed manager update.
        if(pc!=0x140350 && pc!=0x140b78)throw std::runtime_error("Unknown sound worker wake call");
        c->set32(2,0);c->pc=ra;break;
    }
    case 0x1456f8:{
        if(pc!=0x13ae2c || cstring(c->word(4)).substr(0,5)!="SANM/")throw std::runtime_error("Unknown ISO request at 1456F8");
        c->set32(2,find_sab_file(m,c->word(4)+5));c->pc=ra;break;
    }
    case 0x10c528:case 0x10c578:case 0x10c5b8:case 0x10c5f8:case 0x10c780:case 0x10c7c0:{
        const auto owner=u32(invoke_recovered(m,0x10fb38,0)),arg=c->word(4),size=c->word(5);
        u32 result=0;
        if(target==0x10c528)cue_effect_on(m,owner,arg,size,services);
        else if(target==0x10c578)cue_effect_change(m,owner,arg,size);
        else if(target==0x10c5b8)cue_effect_off(m,owner,arg,size);
        else if(target==0x10c5f8)result=cue_effect_busy(m,owner,arg);
        else if(target==0x10c780)result=retained_cue_effect(m,owner,arg);
        else clear_cue_effects(m,owner);
        c->set32(2,result);c->pc=ra;break;
    }
    case 0x152848:{ // 152848 scans 32 sixteen-byte thread records under the kernel lock.
        if(!card_thread)throw std::runtime_error("Thread lookup without native card task");
        u32 p=0;
        for(unsigned i=0;i<32;++i)if(m.read_u32(0x1e40900+16*i)==c->word(4)){p=0x1e40900+16*i;break;}
        c->set32(2,p);c->pc=ra;break;
    }
    case 0x1b50f0:{
        if(card_thread!=0x103ca0 || c->word(4)!=m.read_u32(0x235c20) || (pc!=0x104710 && pc!=0x104728))
            throw std::runtime_error("Unbound ChangeThreadPriority caller");
        const auto next=c->word(5);
        if(next!=19 && next!=25)throw std::runtime_error("Unexpected request thread priority");
        c->set32(2,m.read_u32(0x1357c04));m.write_u32(0x1357c04,next);c->pc=ra;break;
    }
    case 0x1b54e0:
        if(c->word(4)!=0)throw std::runtime_error("Unsupported card FlushCache mode");
        std::atomic_thread_fence(std::memory_order_seq_cst);c->pc=ra;break;
    case 0x1b0670:c->set32(2,allocate_sound_packet(m,c->word(4)));c->pc=ra;break;
    case 0x1b06f8:submit_sound_packet(m,c->word(4));c->pc=ra;break;
    case 0x15fde0:case 0x15fe30:case 0x15ff88:{
        const auto p=c->word(4);
        const bool enabled=!m.read_u32(0x1e497e0); // 175E70(0,0)
        std::uint16_t value=0;
        if(enabled){
            value=target==0x15fde0?m.read_u16(0x1e41c68):target==0x15ff88?
                chart_direction_repeat(m):choice_device_edges(m,0x1e41c60);
        }
        store(p,value,2);c->set32(2,enabled && m.read_u32(0x1e41c60));c->pc=ra;break;
    }
    case 0x19e3e8:{ // Publish the original fade alpha for the native menu.
        const float limit=c->f[12],current=c->f[13];
        const auto alpha=current<=0?0:limit<=current?128:std::int32_t(std::nearbyint(128.f/limit*current));
        m.write_u32(0x20ea0c,u32(alpha));c->set32(2,c->word(4));c->pc=ra;break;
    }
    case 0x1b5280:case 0x1b52b0:{ // Signal/Poll the respective card worker's binary semaphore.
        const bool scan=pc==0x10327c,request=pc==0x104b08 || pc==0x104b10;
        if(!scan && !request)throw std::runtime_error("Unbound memory-card semaphore site");
        const auto event=scan?0x1353000u:0x1353004u;
        m.write_u32(event,target==0x1b5280); // All three call sites discard kernel v0.
        c->pc=ra;break;
    }
    case 0x10d260:FUN_0010d260_0x10d260(ram,c,this);break;
    case 0x114b28:FUN_00114b28_0x114b28(ram,c,this);break;
    case 0x1218f8:FUN_001218f8_0x1218f8(ram,c,this);break;
    case 0x10fb38:case 0x1133a8:case 0x175f78:case 0x121760:case 0x114ae0:
    case 0x10fac0:case 0x10fab8:case 0x10fac8:case 0x10f9b0:case 0x10fa88:case 0x10d868:case 0x10ee18:
    case 0x10d4c8:case 0x10fa68:case 0x1b0ed0:
    case 0x10d5d8:case 0x10d610:case 0x10d638:case 0x10d680:case 0x10d700:case 0x10d720:
    case 0x10d740:case 0x10d748:case 0x10daf0:case 0x10e8d8:case 0x111738:
    case 0x1114f8:case 0x113470:case 0x1134c0:case 0x113468:case 0x1133b0:
    case 0x11dac0:case 0x10f110:case 0x10e630:case 0x101a70:case 0x11e310:case 0x137350:
    case 0x137578:case 0x135618:case 0x10ef18:case 0x10ef90:case 0x10eed0:
    case 0x101ca8:case 0x1397d8:
    case 0x10d750:case 0x1125c8:case 0x121900:case 0x1536a8:case 0x153a70:case 0x175d68:
    case 0x121fc8:
    // The chapter transition calls 121760 on the manager's +854 object.
    // These integer-ABI services are shared with the keyboard system menu.
    case 0x15f800:case 0x112dc0:case 0x121648:case 0x17a0e0:case 0x175d38:
    case 0x204a68:case 0x2049d0: // Slot +32 of the four original menu vtables.
    case 0x121e50:case 0x121f58:case 0x121f98:case 0x121aa8:case 0x121b78:case 0x121be8:
    case 0x122220:case 0x1222b0:case 0x1222f8:
    case 0x1682d8:case 0x1682e0:case 0x1682e8:case 0x1682f0:case 0x1682f8:case 0x168308:
    case 0x168330:case 0x168338:case 0x1686d8:case 0x169e58:
    case 0x101080:case 0x106338:case 0x106690:case 0x10bd50:case 0x19ce48:
    case 0x1abfa0:case 0x1adab0:case 0x1af4b0:case 0x1b15f0:
    case 0x1a1eb0:case 0x1adbd8:case 0x1af6e0:case 0x1fdb50:
        c->set64(2,invoke_recovered(m,target,c->word(4),c->r[5].lo,c->r[6].lo,c->r[7].lo,services));
        c->pc=ra;break;
    default:{
        if(vm_context){
            bool context_allocation=false;
            if(target==0x10fad0)switch(pc){
#define KX3_CONTEXT_ALLOCATION(site,bytes) case site:context_allocation=c->word(4)==bytes;break;
#include "context_allocations.hpp"
#undef KX3_CONTEXT_ALLOCATION
            }
            if(context_allocation){
                // Original one- and two-vtable singletons share this saved allocator.
                constexpr u32 heap=0x1a80000;
                const auto used=m.read_u32(heap);
                if(used>=0x10000)throw std::runtime_error("VM singleton allocation exhausted");
                c->set32(2,heap+16+used);m.write_u32(heap,used+16);
            }else{
                try{c->set64(2,invoke_recovered(m,target,c->word(4),c->r[5].lo,c->r[6].lo,c->r[7].lo,services));}
                catch(const std::exception& e){
                    std::ostringstream msg;msg<<e.what()<<" (VM call 0x"<<std::hex<<pc<<" -> 0x"<<target<<")";
                    throw std::runtime_error(msg.str());
                }
            }
            c->pc=ra;break;
        }
        std::ostringstream error;error<<"Unrecovered chapter/return service 0x"<<std::hex<<target<<" from 0x"<<pc;
        throw std::runtime_error(error.str());
    }
    }
    if(c->pc!=ra || (call && ra!=resume))
        throw std::runtime_error("Incorrect scenario return PC");
    if(frame){
        if(pc==0x113184)frame->sample(m,*services);
        if(pc==0x1131a4 || pc==0x1131c0)frame->result.input_or_context_blocked=c->r[2].lo!=0;
        if(pc==0x1131d8)frame->result.timer_pending=c->r[2].lo!=0;
    }
    return call;
}
}
void advance_card_thread(GuestMemory& m,CardVolume& card,u32 entry){
    // 204C40/204C58 specify 16 KiB stacks, priorities 20/19, and these
    // original entry points. Suspensions and both stacks are checkpointed.
    constexpr u32 max_depth=16;
    const bool scan=entry==0x103640;
    if(!scan && entry!=0x103ca0)throw std::logic_error("Unknown card thread");
    const u32 state=scan?0x1357400:0x1357000,thread_top=scan?0x1360000:0x135c000;
    if(!m.transaction_active())throw std::logic_error("Card request outside worker transaction");
    const u32 wait=m.read_u32(state);
    ExecutionServices services;services.card=&card;
    PS2Runtime runtime{m,&services};runtime.card_thread=entry;
    // 105410 verifies the complete checkpoint in one invocation, including
    // up to 0x40000 / 4 words in the two reserved bank areas.
    runtime.branches=100000;
    if(!wait && scan && m.read_u32(0x1353008)){m.write_u32(runtime.signal(),1);m.write_u32(0x1353008,0);}
    if((!wait || wait==2) && !m.read_u32(runtime.signal()))return;
    R5900Context c;
    // Early native checkpoints can already be suspended without having
    // published a kernel thread handle. Restore that missing bootstrap only.
    const u32 handle=scan?2:3,record=0x1e40900+16*(handle-2),slot=scan?0x235c1c:0x235c20;
    if(m.read_u32(slot)!=handle || !m.read_u32(scan?0x1357c00:0x1357c04)){
        if(m.read_u32(slot)!=handle && m.read_u32(slot) && m.read_u32(slot)!=UINT32_MAX)
            throw std::runtime_error("Unexpected card thread handle");
        if(m.read_u32(record)!=handle && m.read_u32(record) && m.read_u32(record)!=UINT32_MAX)
            throw std::runtime_error("Card thread record in use");
        m.write_u32(slot,handle);m.write_u32(record,handle);m.write_u32(record+8,0);
        m.write_u32(scan?0x1357c00:0x1357c04,scan?20:19);
    }
    if(!wait){
        for(u32 lock:{0x204bc0u,0x204be0u})if(!m.read_u32(lock) || m.read_u32(lock)==UINT32_MAX){
            m.write_u32(lock,lock==0x204bc0?8:9);m.write_u32(lock+4,UINT32_MAX);
            m.write_u32(lock+8,0);m.write_u32(lock+12,lock==0x204bc0?19:0);
        }
        if(!m.read_u32(0x235b70))m.write_u32(0x235b70,0x1354000);
        c.pc=entry;c.set32(28,0x23daf0);c.set32(29,thread_top);c.set32(31,done);
        runtime.frames.push_back(c.pc);
    }else{
        const auto count=m.read_u32(state+4);
        if(wait>3 || !count || count>max_depth || m.read_u32(state+16)!=entry)
            throw std::runtime_error("Invalid saved card thread");
        for(u32 i=0;i<count;++i)runtime.frames.push_back(m.read_u32(state+16+4*i));
        c.pc=m.read_u32(state+8);
        u32 p=state+80;
        auto wide=[&](){const auto v=m.read_u32(p)|(u64(m.read_u32(p+4))<<32);p+=8;return v;};
        for(auto& q:c.r){q.lo=wide();q.hi=wide();}
        for(auto& f:c.f){f=std::bit_cast<float>(m.read_u32(p));p+=4;}
        c.hi=wide();c.lo=wide();c.hi1=wide();c.lo1=wide();
        c.f_acc=std::bit_cast<float>(m.read_u32(p));c.fcr31=m.read_u32(p+4);
        if(wait==2)m.write_u32(runtime.signal(),0);
        if(wait==3 && !runtime.acquire_card_lock(c.word(4)))return;
        if(wait!=3)c.set32(2,wait==2?0:m.read_u32(0x23daf0-0x71e4));
    }
    while(!runtime.frames.empty()){
        const auto body=menu_body(runtime.frames.back());
        if(!body)throw std::runtime_error("Unknown saved card thread frame");
        body(nullptr,&c,&runtime);
        if(runtime.waiting)break;
        runtime.frames.pop_back();
    }
    if(!runtime.waiting || runtime.frames.size()>max_depth || c.in_delay_slot ||
       c.word(29)>thread_top || c.word(29)<thread_top-16384)
        throw std::runtime_error("Invalid card thread suspension");
    m.write_u32(state,runtime.waiting);m.write_u32(state+4,u32(runtime.frames.size()));m.write_u32(state+8,c.pc);
    for(u32 i=0;i<runtime.frames.size();++i)m.write_u32(state+16+i*4,runtime.frames[i]);
    u32 p=state+80;
    auto wide=[&](u64 v){m.write_u32(p,u32(v));m.write_u32(p+4,u32(v>>32));p+=8;};
    for(auto q:c.r){wide(q.lo);wide(q.hi);}
    for(float f:c.f){m.write_u32(p,std::bit_cast<u32>(f));p+=4;}
    wide(c.hi);wide(c.lo);wide(c.hi1);wide(c.lo1);
    m.write_u32(p,std::bit_cast<u32>(c.f_acc));m.write_u32(p+4,c.fcr31);
}
static u64 execute_body(GuestMemory& m,u32 entry,u32 self,u64 a1,u64 a2,u64 a3,ExecutionServices* services,u32 vm_stack){
    std::optional<GuestMemory::Transaction> transaction;
    if(!m.transaction_active())transaction.emplace(m);
    PS2Runtime runtime{m,services};R5900Context c;
    runtime.vm_context=vm_stack!=0;
    // The original parser can clear up to fourteen 0x3480-byte row buffers per update.
    if(entry==0x14d6e8 || entry==0x14df38)runtime.branches=100000;
    if(entry==0x113148)runtime.branches=1'000'000;
    // Post-load prescan passes output pointers to the shared script reader.
    // Give these top-level entries a guest-addressable stack as on the EE.
    const u32 initial_stack=vm_stack?vm_stack:entry==0x14d6e8 || entry==0x14df38 || entry==0x141f10?credits::stack:
        entry==0x10c4e8 || entry==0x120768?0x141c000:stack_top;
    c.pc=entry;c.set32(4,self);c.set64(5,a1);c.set64(6,a2);c.set64(7,a3);
    c.set32(28,0x23daf0);c.set32(29,initial_stack);c.set32(31,done);
    if(entry==0x133f60)FUN_00133f60_0x133f60(nullptr,&c,&runtime);
    else if(entry==0x10d260)FUN_0010d260_0x10d260(nullptr,&c,&runtime);
    else if(entry==0x122070)FUN_00122070_0x122070(nullptr,&c,&runtime);
    else if(entry==0x1218f8)FUN_001218f8_0x1218f8(nullptr,&c,&runtime);
    else if(const auto body=menu_body(entry))body(nullptr,&c,&runtime);
    else throw std::invalid_argument("Unknown scenario return entry");
    if(c.pc!=done || c.word(29)!=initial_stack)throw std::runtime_error("Incomplete scenario return");
    if(!runtime.glyphs.empty() && services && services->text)services->text->stage_glyph_events(runtime.glyphs);
    if(transaction)transaction->commit();
    return c.r[2].lo;
}
std::uint64_t run_scenario_return(GuestMemory& m,u32 entry,u32 self,u64 a1,ExecutionServices* services){
    return execute_body(m,entry,self,a1,0,0,services,0);
}
namespace {
thread_local unsigned vm_depth=0;
struct VmStackFrame {
    u32 top;
    VmStackFrame(){
        if(vm_depth>=32)throw std::runtime_error("Original nested VM calls exhausted the guest stack area");
        top=0x1a00000+0x4000*(++vm_depth);
    }
    ~VmStackFrame(){--vm_depth;}
};
}
std::uint64_t run_vm_context(GuestMemory& m,u32 entry,u32 self,u64 a1,u64 a2,u64 a3,ExecutionServices* services){
    const VmStackFrame frame;
    return execute_body(m,entry,self,a1,a2,a3,services,frame.top);
}
bool resolve_preview_filename(GuestMemory& m,const MediaActiveServices& files,std::string& name,std::string& preview){
    const VmStackFrame frame;
    const u32 buffer=frame.top-64;
    if(name.size()>=23)throw std::runtime_error("Original descriptor name exceeds preview row");
    std::optional<GuestMemory::Transaction> transaction;
    if(!m.transaction_active())transaction.emplace(m);
    m.write_bytes(buffer,{reinterpret_cast<const std::uint8_t*>(name.data()),name.size()});
    m.write_u8(buffer+u32(name.size()),0);
    ExecutionServices services;services.iso_files=&files;
    constexpr u32 original_path=0x2070ab;
    const auto prior=m.bytes(original_path,23);
    std::array<std::uint8_t,23> saved;
    std::copy(prior.begin(),prior.end(),saved.begin());
    const bool replaced=execute_body(m,0x137b98,buffer,0,0,0,&services,buffer)!=0;
    const auto read=[&](u32 at){
        const auto bytes=m.bytes(at,23);const auto end=std::find(bytes.begin(),bytes.end(),0);
        if(end==bytes.end())throw std::runtime_error("Original preview path exceeds descriptor row");
        return std::string(bytes.begin(),end);
    };
    if(replaced){name=read(buffer);preview=read(original_path);}
    m.write_bytes(original_path,saved);
    if(transaction)transaction->commit();
    return replaced;
}
void advance_scene_fade(GuestMemory& m,ExecutionServices* services){
    // 1351BC..1352A8, after 137D78 and before the shared update counter.
    // 139028 can defer the final step while original sound/cue tasks are busy.
    const auto level=m.read_u32(0x2070f0),target=m.read_u32(0x2070f4);
    if(level==target)return;
    const auto step=m.read_u32(0x235fc0);
    const bool down=std::bit_cast<i32>(target)<std::bit_cast<i32>(level);
    const auto next=down?level-step:level+step;
    const bool beyond=down?std::bit_cast<i32>(next)<std::bit_cast<i32>(target):
                           std::bit_cast<i32>(target)<std::bit_cast<i32>(next);
    const auto value=beyond?target:next;m.write_u32(0x2070f0,value);
    if(value!=target)return;
    if(value==128 && run_scenario_return(m,0x139028,0,0,services)){
        m.write_u32(0x2070f0,down?value+1:value-1);return;
    }
    if(m.read_u32(0x2062d0)){
        run_scenario_return(m,0x1407d0,0,0,services);run_scenario_return(m,0x140988,0,0,services);
    }
    if(value==128){
        const auto callback=m.read_u32(0x2070fc);
        if(callback){
            if(callback!=0x10c8d0){
                std::ostringstream err;err<<"Unrecovered scene fade callback 0x"<<std::hex<<callback<<" at 0x135284";
                throw std::runtime_error(err.str());
            }
            run_scenario_return(m,callback,0,0,services);
        }
    }
}
}
