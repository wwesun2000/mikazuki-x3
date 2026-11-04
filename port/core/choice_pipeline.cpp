#include "choice_pipeline.hpp"
#include "control_transfer.hpp"
#include "recovered.hpp"
#include "script_data.hpp"
#include "source_libc.hpp"
#include "system_charts.hpp"
#include <bit>
#include <cmath>
#include <initializer_list>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

namespace kx3 {
namespace {
constexpr std::uint32_t interactive_vtable = 0x22379c;
constexpr std::uint32_t confirm_singleton = 0x235f0c, default_singleton = 0x235f3c;
constexpr std::uint32_t notify_move = 0x1e4ab80, notify_confirm = 0x1e4ab7c;
constexpr std::uint32_t task_table_pointer = 0x2388bc;
constexpr std::uint32_t source_gp = 0x23daf0;
std::int32_t i32(std::uint32_t x) { return std::bit_cast<std::int32_t>(x); }
float f32(std::uint32_t x) { return std::bit_cast<float>(x); }
std::uint64_t sext(std::uint32_t x) {return std::uint64_t(std::int64_t(i32(x)));}

void require_source(const ChoiceServices& services, std::uint32_t entry) {
    if (!services.supports_source(entry)) {
        std::ostringstream error;
        error << "choice: unresolved source dependency 0x" << std::hex << std::setw(8)
              << std::setfill('0') << entry;
        throw std::runtime_error(error.str());
    }
}
std::uint64_t call(ChoiceServices& services, GuestMemory& m, std::uint32_t entry,
                   std::initializer_list<std::uint64_t> args) {
    require_source(services, entry);
    return services.call_source(m, entry, {args.begin(), args.size()});
}
void require_effects(const ChoiceServices& services, std::initializer_list<ChoiceEffectKind> kinds) {
    for (auto kind : kinds) if (!services.supports_effect(kind))
        throw std::runtime_error("choice: frontend effect implementation missing");
}
void check_callback(const GuestMemory& m, const ChoiceServices& services, std::uint32_t slot) {
    if (auto target = m.read_u32(slot)) require_source(services,target);
}
void notify(GuestMemory& m, ChoiceServices& services, std::uint32_t slot, std::uint32_t index) {
    if (auto target = m.read_u32(slot)) call(services,m,target,{index});
}
std::uint64_t helper_predicate(GuestMemory& m,std::uint32_t manager,unsigned opcode,
                               ChoiceServices& services) {
    // 113368(4)/113328(2) ->1133C0 -> context slot3. Handle only proven
    // default/choice wrapper shapes; other contexts keep a real source call.
    const auto entry=opcode==4?0x113368u:0x113328u;
    const auto context=m.read_u32(manager+0x40);
    const auto bridge=m.read_u32(m.read_u32(context)+12);
    const auto helper=m.read_u32(manager+0x280+opcode*4);
    unsigned offset;
    if(bridge==0x120410)offset=0x40;
    else if(bridge==0x11e860)offset=0;
    else return call(services,m,entry,{manager});
    const auto target=m.read_u32(m.read_u32(helper)+offset);
    // Both actual ELF bodies are exactly JR RA; DADDU v0,zero,zero. 134D88
    // was missing a Ghidra function boundary; no boundary is invented here.
    if(target==0x134d08 || target==0x134d88)return 0;
    if(target==0x134bd0 || target==0x134af0)return choice_readback_eligible(m)?1:0;
    return call(services,m,target,{helper,context});
}
bool source_prefix_equal2(const GuestMemory& m,std::uint32_t a,std::uint32_t b) {
    // 1FDF50 with fixed length2 never enters its8/16-byte paths.
    for(unsigned i=0;i<2;++i) {
        const auto x=m.read_u8(a+i),y=m.read_u8(b+i);
        if(x!=y)return false;
        if(x==0)return true;
    }
    return true;
}
}
void copy_name13(GuestMemory& m,std::uint32_t destination,std::uint32_t label) {
    for(unsigned i=0;i<13;++i) {
        const auto byte=m.read_u8(label+i);m.write_u8(destination+i,byte);
        if(byte==0)break;
    }
}
std::uint8_t source_label_category(const GuestMemory& m,std::uint32_t label) {
    for(unsigned i=0;i<18;++i) {
        if(source_prefix_equal2(m,label,m.read_u32(0x20e9a0+i*4)))return std::uint8_t(i);
    }
    return 255;
}
std::uint8_t source_label_chapter(const GuestMemory& m,std::uint32_t label) {
    auto digit=label+2;
    const auto ch=m.read_u8(digit);
    if(ch>='a' && ch<='z')++digit;
    const auto a=m.read_u8(digit),b=m.read_u8(digit+1);
    return (a>='0' && a<='9' && b>='0' && b<='9')?
        std::uint8_t((a-'0')*10+(b-'0')):255;
}
namespace {
bool classify_progress(GuestMemory& m,std::uint32_t label) {
    const auto category=source_label_category(m,label);
    m.write_u8(source_gp-23408,category);
    const auto chapter=source_label_chapter(m,label);
    m.write_u8(source_gp-23407,chapter);
    const bool valid=category<18 && chapter!=0 && chapter!=255;
    m.write_u32(source_gp-23404,valid?1:0);
    if(valid && m.read_u32(source_gp-23388)==0) {
        m.write_u8(source_gp-23400,m.read_u8(source_gp-23408));
        m.write_u8(source_gp-23399,m.read_u8(source_gp-23407));
        // 19C638 copies <=13 bytes including a encountered NUL. It does not
        // clear the remaining buffer or append a terminator after13 non-NULs.
        copy_name13(m,0x1e4abb0,label);
    }
    return valid;
}
std::uint32_t checked_choice(const GuestMemory& m, std::uint32_t manager) {
    auto choice = m.read_u32(manager+8);
    const auto count = m.read_u32(choice+4), focus = m.read_u32(choice+0x168);
    if (count == 0 || count > 10 || focus >= count)
        throw std::runtime_error("choice: invalid option count/focus");
    if (m.read_u32(choice+0xc) != 1 || m.read_u32(choice+0x194) != 0 ||
        m.read_u32(choice+0x1d0) != 0 || m.read_u32(manager+0x808) != 0)
        throw std::runtime_error("choice: special/scripted/autoplay mode not implemented in ordinary pipeline");
    return choice;
}
void ranges(const GuestMemory& m, std::uint32_t choice, std::uint32_t index,
             ChoiceEffectKind kind, std::uint32_t source, ChoiceUpdate& out,
             std::array<std::uint32_t,3> rgb = {}, float value = 0) {
    for (unsigned channel = 0; channel < 2; ++channel) {
        const auto start_field = channel ? 0x118u : 0xc8u;
        const auto end_field = channel ? 0x140u : 0xf0u;
        ChoiceEffect e{kind}; e.source_entry=source; e.channel=channel;
        e.first=i32(m.read_u32(choice+start_field+index*4));
        e.last_inclusive=i32(m.read_u32(choice+end_field+index*4));
        if (e.first < 0 || e.last_inclusive < e.first-1 ||
            e.last_inclusive >= (channel ? 100 : 400))
            throw std::runtime_error("choice: invalid original glyph range");
        e.rgb=rgb; e.value=value; out.pending_effects.push_back(e);
    }
}
bool option_read_state(GuestMemory& m, std::uint32_t manager, std::uint32_t choice, std::uint32_t index) {
    const auto script=m.read_u32(manager+0x38);
    const auto selector=m.read_u32(choice+0x44+index*4), label=m.read_u32(choice+0x1c+index*4);
    const auto id=invoke_script_data(m,0x10fa88,script,selector,label);
    if (invoke_script_data(m,0x10efc0,script,selector,label)) return false;
    return invoke_script_data(m,0x10eff0,script,id,0)!=0;
}
void restore_color(GuestMemory& m,std::uint32_t manager,std::uint32_t choice,ChoiceUpdate& out) {
    const auto focus=m.read_u32(choice+0x168);
    // 175F78 is an actual constant-zero source stub, not a missing setting.
    const std::array<std::uint32_t,3> rgb = m.read_u32(manager+0x744) ?
        std::array<std::uint32_t,3>{92,128,128} : option_read_state(m,manager,choice,focus) ?
        std::array<std::uint32_t,3>{64,64,64} : std::array<std::uint32_t,3>{128,128,128};
    ranges(m,choice,focus,ChoiceEffectKind::glyph_color,0x118150,out,rgb);
}
void move_focus(GuestMemory& m,std::uint32_t manager,std::uint32_t choice,int direction,bool wrap,
                ChoiceServices& services,ChoiceUpdate& out) {
    check_callback(m,services,notify_move);
    require_effects(services,{ChoiceEffectKind::glyph_color,ChoiceEffectKind::pointer_move});
    restore_color(m,manager,choice,out);
    const auto count=m.read_u32(choice+4);
    std::uint32_t index=m.read_u32(choice+0x168);
    if (direction>0) { ++index; if (index>=count) index=wrap?0:count-1; }
    else if (index) --index; else index=wrap?count-1:0;
    m.write_u32(choice+0x168,index);
    notify(m,services,notify_move,index);
    // Source reloads focus after the callback. A callback can alter guest state.
    index=m.read_u32(choice+0x168);
    if (index>=m.read_u32(choice+4)) throw std::runtime_error("choice: callback invalidated focus");
    ChoiceEffect pointer{ChoiceEffectKind::pointer_move}; pointer.source_entry=0x118308;
    pointer.x=float(i32(m.read_u32(choice+0x78+index*4)-18u));
    pointer.y=float(i32(m.read_u32(choice+0xa0+index*4)+6u));
    m.write_u32(0x1e44378+0x10,std::bit_cast<std::uint32_t>(pointer.x));
    m.write_u32(0x1e44378+0x14,std::bit_cast<std::uint32_t>(pointer.y));
    out.pending_effects.push_back(pointer);
    ranges(m,choice,index,ChoiceEffectKind::glyph_color,0x118bf8,out,{128,64,64});
}
std::uint32_t singleton(GuestMemory& m,ChoiceServices& services,std::uint32_t slot,std::uint32_t getter) {
    if (auto p=m.read_u32(slot)) return p;
    return std::uint32_t(call(services,m,getter,{}));
}
void retire_task(GuestMemory& m,std::uint32_t task) {
    const auto base=m.read_u32(task_table_pointer);
    for (std::uint32_t i=0;i<37;++i) {
        const auto p=base+i*48u;
        if (m.read_u32(p) && p==task) {m.write_u32(p+4,1);return;}
    }
}
void begin_confirm(GuestMemory& m,std::uint32_t manager,std::uint32_t choice,
                   ChoiceServices& services,ChoiceUpdate& out) {
    check_callback(m,services,notify_confirm);
    require_effects(services,{ChoiceEffectKind::glyph_color,ChoiceEffectKind::pointer_hide,
        ChoiceEffectKind::glyph_step,ChoiceEffectKind::task_restore,ChoiceEffectKind::task_retire});
    // Preflight allocator before source writes. Normal OBS-001 singleton exists.
    if (!m.read_u32(confirm_singleton)) require_source(services,0x11eb28);
    restore_color(m,manager,choice,out);
    m.write_u32(0x1e44378,0);m.write_u32(0x1e44378+4,0);
    ChoiceEffect hide{ChoiceEffectKind::pointer_hide};hide.source_entry=0x16cc38;hide.channel=2;
    out.pending_effects.push_back(hide);
    // 113430 ->17D3B8 ->179C40, preserve task's original durable fields.
    auto task=m.read_u32(manager+0x58), object=m.read_u32(task+0x2c);
    const auto target=m.read_u32(object+0x18), current=m.read_u32(object+0x10);
    if (!std::isfinite(f32(target)) || !std::isfinite(f32(current)))
        throw std::runtime_error("choice: nonfinite presentation task state");
    m.write_u32(object+0x14,target);m.write_u32(task+0x14,0x17d3e0);
    ChoiceEffect restore{ChoiceEffectKind::task_restore};restore.source_entry=0x17d3b8;
    restore.guest_task=task;restore.guest_object=object;restore.callback=0x17d3e0;
    restore.value=f32(target);restore.x=f32(current);out.pending_effects.push_back(restore);
    const auto focus=m.read_u32(choice+0x168);
    for (std::uint32_t i=0;i<m.read_u32(choice+4);++i)
        if (i!=focus) ranges(m,choice,i,ChoiceEffectKind::glyph_step,0x117e30,out,{},-8.0f);
    notify(m,services,notify_confirm,focus);
    const auto hint=m.read_u32(manager+0x20);
    if (m.read_u32(hint+4) && m.read_u32(hint+0x2c)) {
        const auto hint_task=m.read_u32(hint+0x2c);retire_task(m,hint_task);m.write_u32(hint+0x2c,0);
        ChoiceEffect e{ChoiceEffectKind::task_retire};e.source_entry=0x119e70;e.guest_task=hint_task;
        out.pending_effects.push_back(e);
    }
    m.write_u32(manager+0x40,singleton(m,services,confirm_singleton,0x11eb28));
    out.confirming=true;
}
void complete_confirm(GuestMemory& m,std::uint32_t manager,std::uint32_t choice,
                      ChoiceServices& services,ChoiceUpdate& out) {
    out.confirming=true;
    if (services.glyph_animation_pending()) return;
    require_effects(services,{ChoiceEffectKind::font_position,ChoiceEffectKind::glyph_current});
    if (!m.read_u32(default_singleton)) require_source(services,0x120280);
    ChoiceEffect position{ChoiceEffectKind::font_position};position.source_entry=0x118250;
    position.x=float(i32(m.read_u32(choice+0x16c)));position.y=float(i32(m.read_u32(choice+0x170)));
    out.pending_effects.push_back(position);
    const auto index=m.read_u32(choice+0x168);
    ranges(m,choice,index,ChoiceEffectKind::glyph_current,0x117ee8,out,{},0.0f);
    m.write_u32(manager+0x40,singleton(m,services,default_singleton,0x120280));
    choice_transfer_transactional(m,m.read_u32(manager+0x38),sext(m.read_u32(choice+0x44+index*4)),
                                   m.read_u32(choice+0x1c+index*4),0,services);
    m.write_u32(m.read_u32(manager+0x28)+0x14,1);
    out.confirming=false;out.transferred=true;
}
}

namespace {
struct BackwardTarget {bool found=false;std::uint32_t selector=0,id=0;};
BackwardTarget backward_target(GuestMemory& m,std::uint32_t script,std::uint32_t stop,
                                bool notify_progress,ChoiceServices& services) {
    auto record=std::uint32_t(invoke_script_data(m,0x10e630,script,sext(m.read_u32(script+0xd4)),0));
    auto word1=m.read_u32(record+4);
    for(;;) {
        if((word1&31)==31 || (m.read_u32(record)&0x3fff)==0x3fff)return {};
        word1=m.read_u32(record+4);const auto word0=m.read_u32(record);
        if((word1&31)==((word1>>5)&31) && (word0&0x3fff)==((word0>>14)&0x3fff))return {};
        const auto id=word0&0x3fffu;
        if(id>=m.read_u32(script+0x134))throw std::runtime_error("readback: link outside original history count");
        record=std::uint32_t(invoke_script_data(m,0x10e630,script,id,0));
        if(m.read_u32(record+4)&0x1000000u)return {};
        if((m.read_u32(record)&0x80000000u) || id==stop)return {true,word1&31,id};
        if(notify_progress) {
            const auto label=invoke_script_data(m,0x10fa68,script,id,0);
            call(services,m,0x19c868,{label,1});
        }
        word1=m.read_u32(record+4);
    }
}
void source_variable_push(GuestMemory& m) {
    const auto depth=m.read_u32(0x238684),to=0x238ef0u+(depth<<10);
    // Original101190 captures four LD words before each32-byte store group.
    for(unsigned offset=0;offset<1024;offset+=32) {
        std::array<std::uint8_t,32> group;
        auto from=m.bytes(0x238af0+offset,32);std::copy(from.begin(),from.end(),group.begin());
        m.write_bytes(to+offset,group);
    }
    m.write_u32(0x238684,m.read_u32(0x238684)+1);
}
void readback_palette(GuestMemory& m,std::uint32_t manager,ChoiceUpdate& out) {
    const auto font=m.read_u32(manager+0x3c);
    for(unsigned channel=0;channel<2;++channel) {
        const auto format=m.read_u32(font+channel*4);
        m.write_u8(format+30,0);m.write_u8(format+28,112);m.write_u8(format+29,64);
        m.write_u8(format+34,0);m.write_u8(format+32,0);m.write_u8(format+33,0);
    }
    ChoiceEffect e{ChoiceEffectKind::font_palette};e.source_entry=0x16a9f0;e.rgb={112,64,0};
    e.secondary_rgb={0,0,0};e.guest_object=font;out.pending_effects.push_back(e);
}
}

ChoiceUpdate choice_readback_begin_transactional(GuestMemory& m,std::uint32_t helper,
                                                std::uint32_t manager,std::uint64_t selector,
                                                std::uint64_t label_id,std::uint64_t mode,
                                                ChoiceServices& services) {
    if(!m.transaction_active())throw std::logic_error("readback entry requires caller transaction");
    if(mode!=0)throw std::runtime_error("readback: mode1/2 original forward scan closure is not implemented");
    ChoiceUpdate out;out.handler_return=0;
    const auto script=m.read_u32(helper+0x34);
    m.write_u32(helper+0x38,m.read_u32(manager+0x40));
    m.write_u32(helper+8,std::uint32_t(selector));m.write_u32(helper+12,std::uint32_t(label_id));
    m.write_u32(helper+0x10,std::uint32_t(invoke_script_data(m,0x10d610,script,0,0)));
    m.write_u32(helper+0x14,0);m.write_u32(helper+0x18,1);m.write_u32(helper+0x1c,m.read_u32(manager+0x2a4));
    if(!backward_target(m,script,std::uint32_t(label_id),false,services).found)return out;
    require_effects(services,{ChoiceEffectKind::pointer_hide,ChoiceEffectKind::font_palette,
                             ChoiceEffectKind::task_callbacks,ChoiceEffectKind::task_pause});
    check_callback(m,services,0x1e4ab8c);check_callback(m,services,0x1e4ab9c);
    if(!m.read_u32(0x235f24))require_source(services,0x11f530);
    if(m.read_u32(script+0x148)!=0 || m.read_u32(0x238684)!=0)
        throw std::runtime_error("readback: nested original history/variable stacks require additional recovery");
    const auto formats=m.read_u32(manager+0x2a0);
    if(i32(m.read_u32(formats))<=i32(m.read_u32(formats+4)))
        throw std::runtime_error("readback: original manager format snapshot capacity exceeded");
    (void)invoke_script_data(m,0x10f070,script,0,0);
    source_variable_push(m);
    const auto count=m.read_u32(formats+4),size=m.read_u32(formats+8);
    (void)source_memcpy(m,m.read_u32(formats+12)+count*size,manager+0x294,size);
    m.write_u32(formats+4,m.read_u32(formats+4)+1);
    const auto task=m.read_u32(helper+0x30);
    m.write_u32(task+0x14,0x185e18);m.write_u32(task+0x18,0x185f80);
    ChoiceEffect overlay{ChoiceEffectKind::task_callbacks};overlay.source_entry=0x186050;
    overlay.guest_task=task;overlay.callback=0x185e18;overlay.secondary_callback=0x185f80;
    out.pending_effects.push_back(overlay);
    m.write_u32(helper+4,1);
    m.write_u32(manager+0x29c,0);m.write_u32(manager+0x294,0); // Original111550.
    for(unsigned type:{1u,0u,2u}) {
        const auto pointer=0x1e44200u+type*0xbc;
        if(m.read_u32(pointer)) {
            m.write_u32(pointer,0);m.write_u32(pointer+4,0);
            ChoiceEffect hide{ChoiceEffectKind::pointer_hide};hide.source_entry=0x16c790;hide.channel=type;
            out.pending_effects.push_back(hide);
        }
    }
    readback_palette(m,manager,out);
    const auto current_name=std::uint32_t(invoke_script_data(m,0x10fa68,script,sext(m.read_u32(helper+12)),0));
    if(const auto callback=m.read_u32(0x1e4ab8c))call(services,m,callback,{current_name,1});
    if(classify_progress(m,current_name)) {m.write_u32(0x237f94,1);copy_name13(m,0x1e4abc0,current_name);}
    const auto target=backward_target(m,script,m.read_u32(helper+12),true,services);
    if(target.found) {
        (void)invoke_script_data(m,0x10daf0,script,target.selector,target.id);
        m.write_u32(manager+0x40,singleton(m,services,0x235f24,0x11f530));
        // 116908 ->116E78 returns0 for a distinct previous label. Preserve
        // the exceptional same-source path as a required source dependency.
        if(m.read_u32(script+0xd0)==m.read_u32(helper+8) &&
           m.read_u32(script+0xd4)==m.read_u32(helper+12) && m.read_u32(helper+0x14)==0)
            (void)call(services,m,0x116908,{helper});
    }
    const auto freeze=manager+0x2d0;
    for(unsigned field:{8u,12u}) {
        if(m.read_u32(freeze) && m.read_u32(freeze+field)==0) {
            const auto original=m.read_u32(freeze+4);
            if(original) {
                const auto value=m.read_u32(original+field+12);
                m.write_u32(freeze+field,1);m.write_u32(freeze+field+8,value);m.write_u32(original+field+12,0);
            }
        }
    }
    m.write_u32(helper+0x18,0);
    const auto tasks=m.read_u32(task_table_pointer);
    for(unsigned i=0;i<37;++i) {
        const auto p=tasks+i*48;
        if(m.read_u32(p) && m.read_u32(p+8)!=4) {
            m.write_u32(p+0x24,1);
            ChoiceEffect pause{ChoiceEffectKind::task_pause};pause.source_entry=0x17a0e0;pause.guest_task=p;pause.value=1;
            out.pending_effects.push_back(pause);
        }
    }
    if(const auto callback=m.read_u32(0x1e4ab9c))call(services,m,callback,{});
    out.handler_return=1;out.readback_entered=true;return out;
}

bool choice_readback_eligible(GuestMemory& m) {
    const auto manager=m.read_u32(0x235e40); // Source function ignores input a0.
    if(m.read_u32(manager+0x32c))return false; // 114B28 inline manager32C.
    if(m.read_u32(m.read_u32(manager+0x14)))return false; // 1195A8.
    if(!m.read_u32(m.read_u32(manager+4)))return false; // 1165B0.
    if(m.read_u32(m.read_u32(manager+0x20)+4))return false; // 119DE8.
    if(m.read_u32(manager+0x740) || m.read_u32(manager+0x744) || m.read_u32(manager+0x808))return false;
    const auto script=m.read_u32(manager+0x38);
    const auto label=invoke_script_data(m,0x10d748,script,0,0);
    return invoke_script_data(m,0x10ef90,script,label,0)==0;
}

void choice_progress_label_transactional(GuestMemory& m,std::uint32_t label,ChoiceServices& services) {
    if(!m.transaction_active())throw std::logic_error("Progress registration requires caller transaction");
    ExecutionServices callbacks;callbacks.choice=&services;
    (void)run_vm_context(m,0x19cb50,label,0,0,0,&callbacks);
}

void choice_begin_label_transactional(GuestMemory& m,std::uint32_t label,std::uint64_t readback,ChoiceServices& services) {
    if(!m.transaction_active())throw std::logic_error("Choice registration requires caller transaction");
    ExecutionServices callbacks;callbacks.choice=&services;
    (void)run_vm_context(m,0x19c910,label,readback,0,0,&callbacks);
}

bool source_choice_option_read(GuestMemory& m,std::uint32_t manager,std::uint32_t choice,std::uint32_t index) {
    return option_read_state(m,manager,choice,index);
}

void page_progress_label_transactional(GuestMemory& m,std::uint32_t label,
                                       std::uint64_t reason,ChoiceServices& services) {
    if (!m.transaction_active()) throw std::logic_error("Page registration requires caller transaction");
    ExecutionServices callbacks;callbacks.choice=&services;
    (void)run_vm_context(m,0x19c868,label,reason,0,0,&callbacks);
}

void choice_transfer_transactional(GuestMemory& m,std::uint32_t script,
                                   std::uint64_t selector,std::uint32_t label,
                                   std::uint64_t flag,ChoiceServices& services) {
    if(!m.transaction_active())throw std::logic_error("choice transfer requires caller transaction");
    ExecutionServices callbacks;
    callbacks.choice=&services;
    (void)run_vm_context(m,0x10d868,script,selector,label,flag,&callbacks);
}

std::uint16_t choice_device_edges(GuestMemory& m,std::uint32_t device) {
    if (m.read_u32(device+0xb4)) {
        const auto old=m.read_u16(device+0xba), current=m.read_u16(device+0xb8);
        m.write_u32(device+0xb4,0);m.write_u16(device+0xba,current);
        m.write_u16(device+0xbc,std::uint16_t(~old & current));
    }
    return m.read_u16(device+0xbc);
}

ChoiceUpdate choice_context_atomic(GuestMemory& m,std::uint32_t manager,
                                    const ChoiceInput& input,ChoiceServices& services) {
    GuestMemory::AccessBudget budget(m,8'000'000);
    GuestMemory::Transaction transaction(m);
    auto out=choice_context_transactional(m,manager,input,services);
    transaction.commit();return out;
}

ChoiceUpdate choice_context_transactional(GuestMemory& m,std::uint32_t manager,
                                          const ChoiceInput& input,ChoiceServices& services) {
    if(!m.transaction_active())throw std::logic_error("choice context requires caller transaction");
    ChoiceUpdate out;const auto choice=checked_choice(m,manager);
    const auto context=m.read_u32(manager+0x40);
    if (context && context==m.read_u32(confirm_singleton)) {
        complete_confirm(m,manager,choice,services,out);
    } else {
        if (m.read_u32(context)!=interactive_vtable)
            throw std::runtime_error("choice: unexpected context");
        if (input.mouse_index>=0) {
            if (std::uint32_t(input.mouse_index)>=m.read_u32(choice+4))
                throw std::runtime_error("choice: mouse target outside original options");
            unsigned remaining=m.read_u32(choice+4);
            while (m.read_u32(choice+0x168)!=std::uint32_t(input.mouse_index)) {
                if (remaining-- == 0)
                    throw std::runtime_error("choice: source callback prevents bounded mouse focus navigation");
                const auto direction=m.read_u32(choice+0x168)<std::uint32_t(input.mouse_index)?1:-1;
                move_focus(m,manager,choice,direction,false,services,out);
            }
        } else if (input.edges&0x8040) {
            move_focus(m,manager,choice,1,(input.edges&0x40)==0,services,out);
        } else if (input.edges&0x10) {
            move_focus(m,manager,choice,-1,false,services,out);
        }
        if ((input.edges&0x2100) || input.mouse_confirm) begin_confirm(m,manager,choice,services,out);
    }
    out.focus=m.read_u32(choice+0x168);return out;
}

ChoiceUpdate choice_readback_gate_atomic(GuestMemory& m,std::uint32_t manager,
                                         const ChoiceInput& input,ChoiceServices& services) {
    GuestMemory::AccessBudget budget(m,8'000'000);
    GuestMemory::Transaction transaction(m);
    auto out=choice_readback_gate_transactional(m,manager,input,services);
    transaction.commit();return out;
}

ChoiceUpdate choice_readback_gate_transactional(GuestMemory& m,std::uint32_t manager,
                                                const ChoiceInput& input,ChoiceServices& services) {
    if(!m.transaction_active())throw std::logic_error("choice readback gate requires caller transaction");
    ChoiceUpdate out;out.handler_return=0;
    // Source predicates precede direction tests; they may not be guessed from UI.
    if (helper_predicate(m,manager,4,services) || !(input.edges&0x50) ||
        !helper_predicate(m,manager,2,services)) return out;
    const auto choice=checked_choice(m,manager), helper=m.read_u32(manager+4);
    const auto script=m.read_u32(helper+0x34);
    const auto selector=m.read_u32(script+0xd0), label=m.read_u32(script+0xd4);
    std::uint32_t mode=(input.edges&0x40)?2:1;if(input.edges&0x10)mode=0;
    bool eligible=true;
    if (m.read_u32(m.read_u32(manager+0x40))==interactive_vtable) {
        const auto focus=m.read_u32(choice+0x168);
        if(mode==0)eligible=focus==0;else if(mode==2)eligible=focus==m.read_u32(choice+4)-1;
    } else if(mode==2 && call(services,m,0x117840,{helper,selector,label})) mode=1;
    std::uint64_t entered=0;
    if(eligible) {
        if(mode==0) {
            auto begin=choice_readback_begin_transactional(m,helper,manager,sext(selector),sext(label),mode,services);
            entered=begin.handler_return;out.pending_effects=std::move(begin.pending_effects);
        } else entered=call(services,m,0x1165d8,{helper,manager,selector,label,mode});
    }
    if (entered) {
        // 117AD0 takes held input, distinct from the cached edge sample.
        std::uint16_t direction=input.held&0xd0;
        if(direction&0x10)direction=0x10;
        if(direction&0x40)direction=0x40;
        if(direction&0x80)direction=0x80;
        m.write_u16(helper+0x2c,direction);m.write_u16(helper+0x2e,direction);m.write_u32(helper+0x28,20);
        out.handler_return=1;out.readback_entered=true;
    }
    out.focus=m.read_u32(choice+0x168);return out;
}
}
