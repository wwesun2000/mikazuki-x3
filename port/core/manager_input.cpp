#include "manager_input.hpp"
#include "control_transfer.hpp"
#include "choice_pipeline.hpp"
#include "choice_presentation.hpp"
#include "guest_memory.hpp"
#include "manager_ops.hpp"
#include "recovered.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <stdexcept>

namespace kx3 {
namespace {
using u16=std::uint16_t;
using u32=std::uint32_t;
using u64=std::uint64_t;
using i32=std::int32_t;
constexpr u32 gp=0x23daf0, device_base=0x1e41c60, pointer_base=0x1e44200;
i32 signed_word(u32 x){return std::bit_cast<i32>(x);}
u64 extend(u32 x){return u64(std::int64_t(signed_word(x)));}
u32 manager(GuestMemory& memory){return u32(invoke_manager_ops(memory,0x10fb38,0,0,0,0,gp));}

u32 mapped_device(const GuestMemory& memory,u32 index) {
    return index&0x10 ? memory.read_u32(gp-0x52b8+4*(index&15)) : index;
}
u32 device(const GuestMemory& memory,u32 index) {return device_base+0x130*mapped_device(memory,index);}
bool input_enabled(const GuestMemory& memory,u32 owner,u32 index) {
    return mapped_device(memory,index)!=0 || memory.read_u32(0x1e497e0)==owner;
}
u16 held(const GuestMemory& memory,u32 index=0) {
    return input_enabled(memory,0,index) ? memory.read_u16(device(memory,index)+8) : 0;
}
u16 edges(GuestMemory& memory) {
    return input_enabled(memory,0,0) ? choice_device_edges(memory,device(memory,0)) : 0;
}
u64 hot_context(GuestMemory& memory,u32 cell,u32 getter,ExecutionServices* services) {
    const u32 context=memory.read_u32(cell);
    if(context) return extend(context);
    return invoke_recovered(memory,getter,0,0,0,0,services);
}
void set_context(GuestMemory& memory,u32 owner,u32 context) {memory.write_u32(owner+0x40,context);}

// The source's four independent pointer indicators. +4 is the visibility
// override; 16C998 tests +0 and the actual update function at +B4.
void update_pointer(GuestMemory& memory,u32 index) {
    const u32 p=pointer_base+188*index;
    const float divisor=std::bit_cast<float>(memory.read_u32(p+0x18));
    if(divisor!=0.0f) {
        const float one=std::bit_cast<float>(memory.read_u32(0x236f40));
        for(unsigned axis=0;axis<2;++axis) {
            const u32 coordinate=p+8+4*axis,target=p+16+4*axis;
            if(divisor==one) memory.write_u32(coordinate,memory.read_u32(target));
            else {
                const float old=std::bit_cast<float>(memory.read_u32(coordinate));
                const float desired=std::bit_cast<float>(memory.read_u32(target));
                memory.write_u32(coordinate,std::bit_cast<u32>(old+(desired-old)/divisor));
            }
        }
    }
    const u32 frame=memory.read_u32(p+0xa8),next_time=memory.read_u32(p+0xac)+1;
    const u32 duration=memory.read_u32(p+0x88+4*frame);
    memory.write_u32(p+0xac,next_time);
    if(signed_word(next_time)>=signed_word(duration)) {
        memory.write_u32(p+0xa8,frame+1);memory.write_u32(p+0xac,0);
        if(signed_word(frame+1)>=signed_word(memory.read_u32(p+0x64))) memory.write_u32(p+0xa8,0);
    }
}
void update_pointers(GuestMemory& memory,ExecutionServices* services) {
    for(unsigned index=0;index<4;++index) {
        const auto p=pointer_base+188*index;
        if (!memory.read_u32(p)) continue;
        const auto fn=memory.read_u32(p+0xb4);
        if(fn==0x16ca10) update_pointer(memory,index);
        else if(fn) (void)invoke_recovered(memory,fn,index,0,0,0,services);
    }
}

// 169CC0 ->169D68/169D98/169DB8/169DF0. These iterator fields are durable
// in guest RAM and are updated even when an original inclusive range is empty.
struct GlyphIterator {
    GuestMemory& memory;
    u32 pool,iterator;
    GlyphIterator(GuestMemory& m,u32 channel):memory(m),pool(m.read_u32(channel)),iterator(m.read_u32(pool+12)) {
        const auto vt=m.read_u32(iterator);
        constexpr std::array<u32,4> methods{0x169d68,0x169d98,0x169db8,0x169df0};
        for(unsigned i=0;i<methods.size();++i) if(m.read_u32(vt+4*i)!=methods[i])
            throw std::runtime_error("Input: unresolved source glyph iterator virtual method");
        m.write_u32(iterator+8,0);m.write_u32(iterator+12,m.read_u32(m.read_u32(iterator+4)+4));
    }
    void range(i32 first,i32 last) {
        const i32 count=signed_word(memory.read_u32(memory.read_u32(iterator+4)+4));
        last=std::min(last,count);
        memory.write_u32(iterator+8,u32(first));
        memory.write_u32(iterator+12,last<first?0:u32(last)-u32(first)+1);
    }
    u32 next() {
        const u32 left=memory.read_u32(iterator+12);
        if(signed_word(left)<=0)return 0;
        memory.write_u32(iterator+12,left-1);
        const u32 index=memory.read_u32(iterator+8),owner=memory.read_u32(iterator+4);
        if(signed_word(index)<0 || index>=memory.read_u32(owner+4))
            throw std::runtime_error("Input: source glyph iterator escaped live nodes");
        const u32 node=memory.read_u32(owner+8)+56*index;
        memory.write_u32(iterator+8,index+1);return node;
    }
};

bool source_animation_pending(GuestMemory& memory,u32 owner) {
    const u32 font=memory.read_u32(owner+0x3c);
    bool pending=false;
    for(unsigned channel=0;channel<2;++channel) {
        GlyphIterator nodes(memory,memory.read_u32(font+8+4*channel));
        while(const auto node=nodes.next()) {
            const float delta=std::bit_cast<float>(memory.read_u32(node+8));
            if(delta==0)continue;
            const float limit=delta>0 ? std::bit_cast<float>(memory.read_u32(0x236ef0)):0.0f;
            if(std::bit_cast<float>(memory.read_u32(node+4))!=limit) {pending=true;break;}
        }
    }
    return pending;
}

void set_new_glyph_values(GuestMemory& m,u32 font,u32 opacity,u32 step) {
    // 16B7B0/16B7F0 set defaults on each channel. Existing nodes retain
    // their current and increment until a range or whole-channel operation.
    for(u32 lane:{8u,12u}) {
        const auto atlas=m.read_u32(font+lane);
        m.write_u32(atlas+8,opacity);
        m.write_u32(atlas+12,step);
    }
}

u32 fade_step(GuestMemory& m,u32 numerator,u32 duration) {
    // DIV.S after CVT.S.W, not unsigned conversion or double arithmetic.
    if(!duration)throw std::runtime_error("113900/113A18: EE zero-divide fade requires hardware FPU semantics");
    return std::bit_cast<u32>(std::bit_cast<float>(m.read_u32(numerator)) /
                              static_cast<float>(signed_word(duration)));
}

u64 glyph_fade_defaults(GuestMemory& m,u32 owner,u64 opcode) {
    // 12B690 sets defaults only. Existing glyphs keep their own opacity and step.
    const u32 font=m.read_u32(owner+0x3c),maximum=m.read_u32(0x235f80);
    if(opcode==0x2f || opcode==0x30) {
        set_new_glyph_values(m,font,maximum,0);
    } else if(opcode==0x57 || opcode==0x58) {
        const u32 duration=u32(invoke_recovered(m,0x10d5d8,m.read_u32(owner+0x38),4));
        // The original 175F78(18) returns zero in its JR RA delay slot.
        const bool fade_out=opcode==0x58;
        const u32 opacity=(fade_out==(duration!=0)) ? maximum:0;
        const u32 step=duration ? fade_step(m,fade_out?0x235f84:0x235f80,duration):0;
        set_new_glyph_values(m,font,opacity,step);
    }
    return 0;
}

u64 glyph_fade_group(GuestMemory& m,u32 owner,u64 opcode) {
    const u32 font=m.read_u32(owner+0x3c), script=m.read_u32(owner+0x38);
    const u32 range=owner+0x2f0+(opcode==0x5a||opcode==0x32 ? 12u:0u);
    if(opcode==0x59 || opcode==0x5a) { // 113898/1139A8.
        const u32 duration=u32(invoke_recovered(m,0x10d5d8,script,4));
        for(u32 lane=0;lane<2;++lane) {
            const u32 pool=m.read_u32(m.read_u32(font+8+lane*4));
            m.write_u32(range+lane*4,m.read_u32(pool+4));
        }
        m.write_u32(range+8,fade_step(m,opcode==0x59?0x235e50:0x235e58,duration));
        set_new_glyph_values(m,font,opcode==0x59?m.read_u32(0x235e54):0,0);
    } else if(opcode==0x31 || opcode==0x32) { // 113938/113A48.
        for(u32 lane=0;lane<2;++lane) {
            const u32 atlas=m.read_u32(font+8+lane*4);
            const u32 count=m.read_u32(m.read_u32(atlas)+4);
            GlyphIterator nodes(m,atlas);
            nodes.range(signed_word(m.read_u32(range+4*lane)),signed_word(count-1));
            const u32 step=m.read_u32(range+8);
            while(const u32 node=nodes.next())m.write_u32(node+8,step);
        }
        if(opcode==0x32) {
            const auto reset=m.read_u32(0x235e5c);
            set_new_glyph_values(m,font,reset,reset);
        }
    }
    return 0;
}

u64 glyph_fade_all(GuestMemory& m,u32 owner,u64 opcode) {
    const u32 font=m.read_u32(owner+0x3c);
    const u32 duration=u32(invoke_recovered(m,0x10d5d8,m.read_u32(owner+0x38),4));
    const auto maximum=m.read_u32(0x235f78);
    const auto current=(opcode==0x5c)==(duration!=0) ? maximum : 0u;
    const auto step=duration ? fade_step(m,opcode==0x5c ? 0x235f7c:0x235f78,duration) : 0u;
    // 12B300 orders these two whole-pool passes differently at duration zero.
    for(unsigned pass=0;pass<2;++pass) {
        const bool set_opacity=(pass==0)==(duration!=0);
        for(u32 lane:{8u,12u}) {
            GlyphIterator nodes(m,m.read_u32(font+lane));
            while(const u32 node=nodes.next())m.write_u32(node+(set_opacity?4:8),set_opacity?current:step);
        }
    }
    return 0;
}
u64 predicate(GuestMemory& memory,u32 owner,u32 index,ExecutionServices* services) {
    const u32 helper=memory.read_u32(owner+0x280+4*index),context=memory.read_u32(owner+0x40);
    const u32 bridge=memory.read_u32(memory.read_u32(context)+12);
    return invoke_recovered(memory,bridge,context,extend(helper),0,0,services);
}

u64 menu_test(GuestMemory& memory,u32 entry,ExecutionServices* services) {
    const u32 owner=manager(memory);
    if(entry==0x121e50) {
        if(!(edges(memory)&0x1000))return 0; // Actual175F78(0xE) is constant zero.
        if(memory.read_u32(owner+0x808)) {
            memory.write_u32(owner+0x808,0);
            if(invoke_recovered(memory,0x116180,owner+0x834,0,0,0,services))return 0;
        }
        return predicate(memory,owner,1,services)!=0;
    }
    if(entry==0x122220) return !memory.read_u32(owner+0x808) && (held(memory)&8) && predicate(memory,owner,1,services);
    if(!memory.read_u32(owner+0x744) || memory.read_u32(owner+0x808))return 0;
    const u32 context=memory.read_u32(owner+0x40);
    if(context!=hot_context(memory,gp-31676,0x11fe00,services) &&
       context!=hot_context(memory,gp-31672,0x11ffb0,services) &&
       context!=hot_context(memory,0x235f04,0x11e6c8,services))return 0;
    if(!(edges(memory)&0x1000))return 0;
    if(memory.read_u16(0x238af0+2*0xb9)!=7)return 1;
    (void)invoke_recovered(memory,0x116180,owner+0x834,1,0,0,services);return 0;
}


}

void color_source_glyph_range(GuestMemory& m,u32 channel,i32 first,i32 last,const std::array<u32,3>& rgb) {
    GlyphIterator nodes(m,channel);nodes.range(first,last);
    while(const u32 node=nodes.next()) {
        m.write_u8(node+2,std::uint8_t(rgb[2]));m.write_u8(node,std::uint8_t(rgb[0]));m.write_u8(node+1,std::uint8_t(rgb[1]));
    }
}

bool alternate_label_armed(const GuestMemory& m,u32 owner) {
    // 113094..1130C0 queries 11A3C8 and the default context before testing Circle.
    const auto object=m.read_u32(owner+0x2c);
    return object && m.read_u32(object) && m.read_u32(owner+0x40)==m.read_u32(0x235f3c);
}
bool has_manager_input(u32 entry) noexcept {
    switch(entry) {
    case 0x12ba68:case 0x12b300:case 0x12b690:case 0x12bdd0:return true;
    case 0x112f78:case 0x113818:case 0x113888:case 0x11e748:case 0x11e608:
    case 0x113368:case 0x113328:case 0x112d40:case 0x120130:case 0x11ff20:case 0x11e860:
    case 0x134d78:case 0x134d80:case 0x134c50:case 0x134c68:
    case 0x134a28:case 0x134a40:case 0x134930:
    case 0x134868:case 0x134880:case 0x1346d8:case 0x1346f0:
    case 0x134d08:case 0x134d88:case 0x134898:case 0x134708:case 0x134c80:
    case 0x134af0:case 0x134bd0:case 0x134790:case 0x1347b8:case 0x1345c8:case 0x134658:
    case 0x121760:case 0x121e50:case 0x122220:case 0x121aa8:case 0x15f800:case 0x15f848:case 0x15f770:case 0x15f8c8:
    case 0x122620:case 0x1162d8:case 0x17a0e0:case 0x175d38:
    case 0x112dc0:case 0x112e48:case 0x114e90:case 0x114e50:
    case 0x15f040:case 0x15f168:case 0x15fe30:case 0x15fde0:case 0x15fec8:
    case 0x16c998:case 0x16ca10:case 0x16b8a0:return true;
    default:return false;
    }
}

void advance_source_glyphs(GuestMemory& memory,u32 font) {
    GuestMemory::AccessBudget budget(memory,8'000'000);
    GuestMemory::Transaction transaction(memory);
    if(!memory.read_u32(font+0x28)) {
        // 16BAB8 invokes 1697D0 for primary, then ruby. The original advances
        // each live glyph before submitting its sprite. The modern renderer
        // consumes these resulting fields through its separate frame snapshot.
        for(unsigned lane=0;lane<2;++lane) {
            GlyphIterator nodes(memory,memory.read_u32(font+8+4*lane));
            while(const u32 node=nodes.next()) {
                const float step=std::bit_cast<float>(memory.read_u32(node+8));
                if(step==0.0f)continue;
                const float value=std::bit_cast<float>(memory.read_u32(node+4))+step;
                if(value<=0.0f) {
                    memory.write_u32(node+8,0);memory.write_u32(node+4,0);
                } else {
                    const u32 limit_bits=memory.read_u32(0x236f20);
                    if(std::bit_cast<float>(limit_bits)<=value) {
                        memory.write_u32(node+4,limit_bits);memory.write_u32(node+8,0);
                    } else memory.write_u32(node+4,std::bit_cast<u32>(value));
                }
            }
        }
    }
    transaction.commit();
}

std::optional<bool> context_input_predicate(const GuestMemory& m,u32 owner,u32 method){
    switch(method){
    case 0x134a28:case 0x134a40:case 0x134930:
        return !m.read_u32(owner+0x740) && m.read_u32(owner+0x44) && !m.read_u32(0x2388d8);
    case 0x134868:case 0x134880:case 0x134790:case 0x1347b8:
        return m.read_u32(owner+0x740)==0;
    case 0x1346d8:case 0x1346f0:case 0x1345c8:case 0x134658:
        return !m.read_u32(owner+0x32c) && !m.read_u32(m.read_u32(owner+0x14)) &&
               !m.read_u32(m.read_u32(owner+0x20)+4) && !m.read_u32(owner+0x740) && !m.read_u32(owner+0x744);
    default:return std::nullopt;
    }
}
u64 invoke_manager_input(GuestMemory& memory,u32 entry,u32 self,u64 a1,u64 a2,u64 a3,ExecutionServices* services) {
    switch(entry) {
    case 0x16b8a0: { // 168B60 over primary and ruby glyph nodes.
        for(u32 lane:{8u,12u}){
            GlyphIterator nodes(memory,memory.read_u32(u32(a1)+lane));
            while(const auto node=nodes.next())memory.write_u32(node+8,self);
        }
        return 0;
    }
    case 0x12b690:return glyph_fade_defaults(memory,manager(memory),a1);
    case 0x12ba68:return glyph_fade_group(memory,manager(memory),a1);
    case 0x12b300:return glyph_fade_all(memory,manager(memory),a1);
    case 0x12bdd0: {
        const u32 owner=manager(memory);
        if(!source_animation_pending(memory,owner))return 0;
        (void)invoke_recovered(memory,0x10d700,memory.read_u32(owner+0x38),a1);
        return 1;
    }
    case 0x112f78:case 0x113818:case 0x113888:case 0x11e748:case 0x11e608:case 0x121760:
        return run_vm_context(memory,entry,self,a1,a2,a3,services);
    case 0x113368:return predicate(memory,self,4,services);
    case 0x113328:return predicate(memory,self,2,services);
    case 0x112d40:return predicate(memory,self,3,services);
    case 0x120130:case 0x11ff20:case 0x11e860: {
        const auto helper=u32(a1),offset=entry==0x120130?0x3cu:entry==0x11ff20?0x38u:0u;
        return invoke_recovered(memory,memory.read_u32(memory.read_u32(helper)+offset),helper,extend(self),a2,a3,services);
    }
    case 0x134d08:case 0x134d78:case 0x134d80:case 0x134d88:case 0x134898:case 0x134708:case 0x134c80:return 0;
    case 0x134c50:case 0x134c68:case 0x134af0:case 0x134bd0:return choice_readback_eligible(memory);
    case 0x134a28:case 0x134a40:case 0x134930:case 0x134868:case 0x134880:case 0x134790:case 0x1347b8:
    case 0x1346d8:case 0x1346f0:case 0x1345c8:case 0x134658:
        return context_input_predicate(memory,manager(memory),entry).value();
    case 0x121e50:case 0x122220:case 0x121aa8:return menu_test(memory,entry,services);
    case 0x15f040:case 0x15f168: {
        const auto p=device(memory,self);
        const auto value=entry==0x15f040?memory.read_u16(p+8):choice_device_edges(memory,p);
        const auto available=memory.read_u32(p);memory.write_u16(u32(a1),value);return available!=0;
    }
    case 0x15fe30:case 0x15fde0:case 0x15fec8: {
        if(!input_enabled(memory,0,0)) {
            if(entry==0x15fec8)memory.write_u16(u32(a1),0);
            memory.write_u16(self,0);return 0;
        }
        if(entry!=0x15fe30) (void)invoke_manager_input(memory,0x15f040,0,self,0,0,services);
        if(entry!=0x15fde0) return invoke_manager_input(memory,0x15f168,0,entry==0x15fec8?a1:self,0,0,services);
        return memory.read_u32(device(memory,0))!=0;
    }
    case 0x15f770:{
        const auto index=mapped_device(memory,self),pad=device(memory,self);
        if(!memory.read_u32(0x207c0c+4*mapped_device(memory,index)) || !memory.read_u32(pad+64))return 0;
        (void)invoke_recovered(memory,0x1536a8,0x207c58,0,0,0,services);
        memory.write_u32(pad+84,u32(a1));memory.write_u32(pad+80,4);
        (void)invoke_recovered(memory,0x153a70,0x207c58,0,0,0,services);return 1;
    }
    case 0x15f8c8:{
        (void)invoke_recovered(memory,0x1536a8,0x207c58,0,0,0,services);
        const auto pad=device(memory,self);const bool active=memory.read_u32(pad+72)||memory.read_u32(pad+80);
        (void)invoke_recovered(memory,0x153a70,0x207c58,0,0,0,services);return active;
    }
    case 0x15f848: {
        constexpr u32 lock=0x207c58;
        (void)invoke_recovered(memory,0x1536a8,lock,0,0,0,services);
        const u32 p=device(memory,self);const bool available=memory.read_u32(p+0x40)!=0;
        if(available && (memory.read_u32(p+0x48)||memory.read_u32(p+0x50)))memory.write_u32(p+0x50,1);
        (void)invoke_recovered(memory,0x153a70,lock,0,0,0,services);return available;
    }
    case 0x15f800: {
        const auto first=invoke_manager_input(memory,0x15f848,0,0,0,0,services);
        const auto second=invoke_manager_input(memory,0x15f848,1,0,0,0,services);
        return first && second;
    }
    case 0x122620:
        if(memory.read_u32(self+4)) (void)invoke_recovered(memory,0x121900,memory.read_u32(self+8),0,0,0,services);
        return 0;
    case 0x1162d8:
        if(memory.read_u32(self)) (void)invoke_recovered(memory,0x116298,self,0,0,0,services);
        return 0;
    case 0x175d38: {
        const auto cell=0x1e497b0u+4*self+12;
        if(memory.read_u32(cell))return 0;memory.write_u32(cell,1);return 1;
    }
    case 0x17a0e0: {
        const auto tasks=memory.read_u32(0x2388bc);
        for(unsigned i=0;i<37;++i){const u32 p=tasks+i*48;if(memory.read_u32(p)&&memory.read_u32(p+8)!=4)memory.write_u32(p+36,1);}
        return 0;
    }
    case 0x112dc0:case 0x112e48: {
        const bool entering=entry==0x112dc0;
        if(entering==bool(memory.read_u32(self+0x2ac)))return 0;
        if(entering) memory.write_u32(self+0x2b0,u32(a1));
        memory.write_u32(self+0x2ac,entering);
        if(entering && a1){memory.write_u32(self+0x2a8,memory.read_u32(self+0x40));set_context(memory,self,u32(hot_context(memory,gp-31680,0x11fc90,services)));}
        if(!entering && memory.read_u32(self+0x2b0))set_context(memory,self,memory.read_u32(self+0x2a8));
        memory.write_u32(memory.read_u32(self+0x3c)+0x28,entering);
        for(unsigned i=0;i<4;++i)memory.write_u32(pointer_base+188*i+4,entering);
        if(!entering){memory.write_u32(gp-30768,0);memory.write_u32(gp-30752,0);}
        const auto helper=memory.read_u32(self+4);
        if(memory.read_u32(helper+4)) (void)invoke_recovered(memory,entering?0x186020:0x186050,memory.read_u32(helper+0x30),0,0,0,services);
        return 0;
    }
    case 0x114e90:case 0x114e50: {
        const bool set=entry==0x114e90;
        if(set==bool(memory.read_u32(self+20)))return 0;
        memory.write_u32(self+20,set);
        if(set)memory.write_u32(self+16,memory.read_u32(self+12));
        const auto value=set?u32(a1):memory.read_u32(self+16);
        memory.write_u32(self+12,value);
        return invoke_recovered(memory,0x1358f8,value,0,0,0,services);
    }
    case 0x16c998:update_pointers(memory,services);return 0;
    case 0x16ca10:update_pointer(memory,self);return 0;
    default:throw std::invalid_argument("Unrecovered manager input source entry");
    }
}
}
