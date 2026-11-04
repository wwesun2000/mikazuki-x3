#include "page_control.hpp"
#include "choice_pipeline.hpp"
#include "guest_memory.hpp"
#include "recovered.hpp"
#include "source_libc.hpp"
#include "text_driver.hpp"
#include <bit>
#include <stdexcept>

namespace kx3 {
namespace {
using u16=std::uint16_t;
using u32=std::uint32_t;
using u64=std::uint64_t;
using i32=std::int32_t;
constexpr u32 gp=0x23daf0;
i32 sw(u32 x){return std::bit_cast<i32>(x);}
u64 sx(u32 x){return u64(std::int64_t(sw(x)));}
u32 manager(GuestMemory& m){return u32(invoke_recovered(m,0x10fb38,0));}

class PageSourceCallbacks final:public ChoiceServices {
public:
    explicit PageSourceCallbacks(ExecutionServices* services):services_(services){}
    bool supports_source(u32 entry) const override {
        return services_ && services_->choice && services_->choice->supports_source(entry);
    }
    u64 call_source(GuestMemory& m,u32 entry,std::span<const u64> args) override {
        if(!supports_source(entry))throw std::runtime_error("Page-end source callback unavailable");
        return services_->choice->call_source(m,entry,args);
    }
    bool supports_effect(ChoiceEffectKind) const override{return false;}
    bool glyph_animation_pending() const override{throw std::runtime_error("Page progress callback has no rendering responsibility");}
private:
    ExecutionServices* services_;
};

u64 hot_context(GuestMemory& m,u32 cell,u32 getter,ExecutionServices* services) {
    const auto value=m.read_u32(cell);
    if(value)return sx(value);
    return invoke_recovered(m,getter,0,0,0,0,services);
}
u32 font_value(GuestMemory& m,u32 font,u32 offset) {
    const u32 format=m.read_u32(font),method=m.read_u32(m.read_u32(format)+offset);
    u32 expected=offset==0?0x1682e8:offset==4?0x1682f0:offset==8?0x168338:0x168330;
    if(method!=expected)throw std::runtime_error("Page: unsupported source formatter getter");
    return u32(invoke_recovered(m,method,format));
}

void line_advance(GuestMemory& m,u32 font) {
    m.write_u32(m.read_u32(font)+4,m.read_u32(font+16));
    const u32 format=m.read_u32(font);
    const u32 size=font_value(m,font,8);
    m.write_u32(format+8,m.read_u32(format+8)+size+m.read_u32(format+24));
    m.write_u32(font+32,m.read_u32(font+32)+1);
}
// 133B28 measures subsequent source text, then restores the relative PC.
// 133A40 queries each packed character; 133930 queries the second byte of
// each pair in a name substitution, as the original LBU at 1339D4 does.
void center_line(GuestMemory& m, ExecutionServices* services) {
    const auto owner=manager(m), script=m.read_u32(owner+0x38), font=m.read_u32(owner+0x3c);
    const auto initial=invoke_recovered(m,0x10d610,script,0);
    const auto width=m.read_u32(font+24)-font_value(m,font,0)+1u;
    auto read=[&](u32 n) {return u32(invoke_recovered(m,0x10d5d8,script,n));};
    u32 measured=0;
    for(;;) {
        const auto op=read(1);
        const auto spacing=m.read_u32(m.read_u32(font)+20);
        bool end=false;
        if(op==2) {
            for(auto high=read(1);high!=3;high=read(1)) {
                if(high==0x21)continue;
                measured+=u32(invoke_recovered(m,0x16b910,font,(high<<8)|read(1)))+spacing;
            }
        } else if(op>=0xd && op<=0x11) {
            constexpr u32 modes[]={0,1,4,2,3};
            auto p=u32(invoke_recovered(m,0x10d3d0,script,modes[op-0xd]));
            const auto n=source_strlen(m,p);
            for(u32 i=0;i<n;i+=2)measured+=u32(invoke_recovered(m,0x16b910,font,m.read_u8(p+i+1)))+spacing;
        } else if(op==4 || op==0xb || op==0x1a || op==0x1b || op==0x6a || op==0x6b || op==0x85) {
            end=true;
        } else {
            (void)invoke_recovered(m,0x111738,owner,0,op,0,services);
        }
        measured-=m.read_u32(m.read_u32(font)+20);
        if(end || sw(width)<sw(measured))break;
    }
    (void)invoke_recovered(m,0x10d700,script,initial);
    if(sw(width)>=sw(measured))
        (void)invoke_recovered(m,0x16a8c8,font,u32(sw(width-measured)/2),0,0,services);
}
void place_indicator(GuestMemory& m,u32 type,u32 x,u32 y) {
    const u32 target=0x1e44200+188*type;
    const u32 fx=std::bit_cast<u32>(float(sw(x)));
    const u32 fy=std::bit_cast<u32>(float(sw(y)));
    m.write_u32(target,1);m.write_u32(target+16,fx);m.write_u8(target+0xb3,128);
    m.write_u32(target+20,fy);m.write_u32(target+0xa8,0);
    m.write_u32(target+0xb4,0x16ca10);m.write_u32(target+0xb8,0x16ce28);m.write_u8(target+0xb0,128);
    m.write_u32(target+4,0);m.write_u32(target+0xac,0);
    m.write_u32(target+8,fx);m.write_u32(target+12,fy);m.write_u8(target+0xb1,128);m.write_u8(target+0xb2,128);
}
void show_indicator(GuestMemory& m,u32 type) {
    const u32 font=m.read_u32(gp-21140);
    u32 x=font_value(m,font,0),y=font_value(m,font,4);
    if(type==1 && sw(m.read_u32(font+24))<sw(x+28)) {
        line_advance(m,font);x=font_value(m,font,0);y=font_value(m,font,4);
    }
    place_indicator(m,type,x+(type==1?4u:0u),y+6);
}
void hide_indicator(GuestMemory& m,u32 type) {
    const u32 p=0x1e44200+type*188;m.write_u32(p+4,0);m.write_u32(p,0);
}
u16 press(GuestMemory& m) {return m.read_u32(0x1e497e0)==0 ? choice_device_edges(m,0x1e41c60):0;}

void page_visit(GuestMemory& m,u32 script,u64 id,u64 save_flag,u64 repeat,ExecutionServices* services) {
    const auto record=u32(invoke_recovered(m,0x10e630,script,id));
    const auto label=u32(invoke_recovered(m,0x10fa68,script,id));
    m.write_u32(record,m.read_u32(record)|0x10000000u);
    if(m.read_u32(script+0x168)) {
        PageSourceCallbacks callbacks(services);
        if(!repeat) {
            m.write_u32(script+0x184,label);m.write_u32(script+0x180,0);
            choice_progress_label_transactional(m,label,callbacks);
        } else {
            const u32 previous=m.read_u32(script+0x184);
            const bool same=previous && source_strcmp(m,label,previous)==0;
            if(!same || m.read_u32(script+0x180))choice_progress_label_transactional(m,label,callbacks);
            m.write_u32(script+0x184,label);m.write_u32(script+0x180,0);
        }
    }
    if(save_flag) {
        const u32 owner=manager(m),helper=m.read_u32(owner+4);
        if(!m.read_u32(helper+4) && !m.read_u32(script+0x148))
            (void)invoke_recovered(m,0x104e10,0,0,0,0,services);
    }
}

u64 readback_redirect(GuestMemory& m,u32 hint,u64 lines,ExecutionServices* services) {
    const auto owner=manager(m),script=m.read_u32(owner+0x38),font=m.read_u32(owner+0x3c);
    if(!m.read_u32(hint+4) || !m.read_u32(hint+8) || std::bit_cast<std::int64_t>(lines)<=4)return 0;
    if(sw(m.read_u32(font+16))<sw(font_value(m,font,0)))line_advance(m,font);
    m.write_u32(owner+0x2b8,0);m.write_u32(owner+0x2b4,0);m.write_u32(hint+8,0);
    m.write_u32(0x235b3c,1);
    (void)invoke_recovered(m,0x10db48,script,sx(m.read_u32(hint+16)),sx(m.read_u32(hint+20)),0,services);
    return 1;
}
u64 enter_wait(GuestMemory& m,u64 opcode,ExecutionServices* services) {
    const auto owner=manager(m),redirect=m.read_u32(owner+0x2c),script=m.read_u32(owner+0x38);
    if(m.read_u32(redirect))
        (void)invoke_recovered(m,0x10daf0,script,sx(m.read_u32(redirect+12)),sx(m.read_u32(redirect+16)),0,services);
    else if(opcode!=0x0c) {
        m.write_u32(owner+0x40,u32(hot_context(m,0x235f38,0x11ffb0,services)));
        show_indicator(m,1);
    }
    return 1;
}
u64 finish_page(GuestMemory& m,u64 opcode,ExecutionServices* services) {
    auto owner=manager(m);
    if(m.read_u32(owner+0x2c0))(void)invoke_recovered(m,0x10edc0,m.read_u32(owner+0x38));
    owner=manager(m);
    const auto hint=m.read_u32(owner+0x20),special=m.read_u32(owner+0x30);
    if(m.read_u32(hint+4) && readback_redirect(m,hint,5,services))return 0;
    if(m.read_u32(special)) {(void)invoke_recovered(m,0x11a5c8,special,0,0,0,services);return 0;}
    if(m.read_u32(owner+0x808))(void)invoke_recovered(m,0x115cd8,owner+0x804);
    (void)invoke_page_control(m,0x123600,0,0,0,0,services);
    return enter_wait(m,opcode,services);
}

bool wait_accept(GuestMemory& m,u16 input) {
    const auto owner=manager(m),clock=m.read_u32(owner+0x24);
    if(m.read_u32(clock)) {
        const auto next=m.read_u32(clock+16)+1;
        m.write_u32(clock+16,next);
        if(sw(next)<sw(m.read_u32(clock+12)))return false;
        m.write_u32(clock+16,0);return true;
    }
    if(m.read_u32(owner+0x808)) {
        // 115C58. The original1160D0 and175F78(1) both return0.
        auto remaining=m.read_u32(owner+0x814);
        if(!m.read_u32(gp-32668)) {
            --remaining;if(sw(remaining)<0)remaining=0;
            m.write_u32(owner+0x814,remaining);
        }
        if(sw(remaining)<1)return true;
    }
    return (input&0x2100)!=0;
}

u64 sequence_input(GuestMemory& m,u32 object,ExecutionServices* services) {
    const u16 input=press(m);const u32 index=m.read_u8(object+4);
    if(index>=12)return 0;
    const u32 owner=manager(m);
    if(m.read_u32(owner+0x808)) {
        // The source random draw includes platform semaphore calls.
        if(invoke_recovered(m,0x17aa28,0,1,0,0,services)==0)m.write_u16(0x238af0+2*230,1);
        m.write_u32(object,0);return 1;
    }
    if(input & m.read_u16(0x22a420+index*2)) {
        m.write_u8(object+4,std::uint8_t(index+1));
        if(index+1==12) {m.write_u32(object,0);m.write_u16(0x238af0+2*230,1);return 1;}
    } else if(input&0xff09) m.write_u8(object+4,12);
    return 0;
}

u64 wait_update(GuestMemory& m,u32 entry,u32 owner,ExecutionServices* services) {
    u16 input=press(m);
    if(entry==0x120030) {
        const auto sequence=m.read_u32(owner+0x14);
        if(m.read_u32(sequence) && sequence_input(m,sequence,services))input|=0x2100;
        if(!wait_accept(m,input))return 1;
        if(m.read_u32(sequence))m.write_u32(sequence,0);
        m.write_u32(owner+0x40,u32(hot_context(m,0x235f3c,0x120280,services)));
        hide_indicator(m,1);return 0;
    }
    if(wait_accept(m,input)) {
        m.write_u32(owner+0x40,u32(hot_context(m,0x235f3c,0x120280,services)));
        hide_indicator(m,0);
    }
    return 1;
}

void clear_page(GuestMemory& m,u32 owner,ExecutionServices* services) {
    if(services && services->text)services->text->stage_page_clear();
    m.write_u32(owner+0x2e8,0);m.write_u32(owner+0x2ec,0);
    auto font=m.read_u32(owner+0x3c);
    const u32 initial=m.read_u32(0x235e44);
    m.write_u32(m.read_u32(font+8)+8,initial);m.write_u32(m.read_u32(font+12)+8,initial);
    font=m.read_u32(owner+0x3c);
    m.write_u32(m.read_u32(font+8)+12,0);m.write_u32(m.read_u32(font+12)+12,0);
    font=m.read_u32(owner+0x3c);
    const auto x=m.read_u32(font+16),y=m.read_u32(font+20);
    (void)invoke_recovered(m,0x16a950,font,x,y,0,services);m.write_u32(font+32,0);
    font=m.read_u32(owner+0x3c);
    for(unsigned lane=0;lane<2;++lane) {
        const auto channel=m.read_u32(font+8+lane*4);
        m.write_u32(channel+36,0);m.write_u32(channel+40,0);m.write_u32(channel+44,0);
        m.write_u32(m.read_u32(channel)+4,0);
    }
}

void prepass09(GuestMemory& m,ExecutionServices* services) {
    const auto owner=manager(m),script=m.read_u32(owner+0x38),font=m.read_u32(owner+0x3c);
    const auto saved_offset=invoke_recovered(m,0x10d610,script,0);
    const auto style=font_value(m,font,16),size=font_value(m,font,8);
    auto read=[&](unsigned length){return invoke_recovered(m,0x10d5d8,script,length);};
    u32 width=0;bool done=false;
    while(!done) {
        const auto op=u32(read(1));
        switch(op) {
        case 2: {
            while(read(1)==0x21){}
            (void)invoke_recovered(m,0x10d610,script,u64(-1));
            width=u32(invoke_recovered(m,0x16b910,font,read(2)));done=true;break;
        }
        case 4:case 9:case 0x1a:case 0x65:case 0x66:case 0x6a:case 0x6b:case 0x6c:case 0x85:done=true;break;
        case 0xd:case 0xe:case 0xf:case 0x10:case 0x11: {
            constexpr unsigned modes[]={0,1,4,2,3};
            const auto address=u32(invoke_recovered(m,0x10d3d0,script,modes[op-0xd]));
            const u16 unit=(u16(m.read_u8(address))<<8)|m.read_u8(address+1);
            width=u32(invoke_recovered(m,0x16b910,font,unit))+m.read_u32(m.read_u32(font)+20);
            done=true;break;
        }
        case 0x42:case 0x43:case 0x4c: {
            const auto handler=m.read_u32(owner+0x5c+4*op),context=m.read_u32(owner+0x40);
            (void)invoke_recovered(m,m.read_u32(m.read_u32(context)+8),context,sx(handler),0,op,services);break;
        }
        case 0x46:width+=u32(read(1));break;
        case 0x4d:width+=u32(read(2));break;
        default:(void)invoke_recovered(m,0x111738,owner,0,op,0,services);break;
        }
    }
    (void)invoke_recovered(m,0x10d700,script,saved_offset);
    if(style!=255)m.write_u32(m.read_u32(font)+16,style);
    const auto restore_size=size?size:m.read_u32(m.read_u32(0x236f30)+16);
    if(restore_size!=255)m.write_u32(m.read_u32(font)+12,restore_size);
    if(sw(width)>0 && sw(m.read_u32(font+24))<sw(font_value(m,font,0)+width))line_advance(m,font);
}
}

bool has_page_control(u32 entry) noexcept {
    switch(entry){
    case 0x133b28:case 0x122900:case 0x1243e8:case 0x123600:case 0x123558:case 0x10eca0:case 0x19cb50:
    case 0x1114f8:case 0x16cb40:case 0x16cad0:case 0x16cbf8:case 0x16cc38:case 0x16a998:case 0x119eb0:
    case 0x120030:case 0x11fe80:case 0x1200f8:case 0x11fee8:case 0x120160:
    case 0x122ef8:case 0x1231c0:case 0x123448:return true;
    default:return false;
    }
}
u64 invoke_page_control(GuestMemory& m,u32 entry,u32 self,u64 a1,u64 a2,u64 a3,ExecutionServices* services) {
    switch(entry){
    case 0x16cbf8:place_indicator(m,2,self,u32(a1)+6);m.write_u32(0x1e44390,m.read_u32(0x236f48));return 0;
    case 0x16cc38:hide_indicator(m,2);return 0;
    case 0x133b28: center_line(m,services);return 0;
    case 0x122900: {
        const auto owner=manager(m), font=m.read_u32(owner+0x3c), readback=m.read_u32(owner+0x20);
        line_advance(m,font);
        if(m.read_u32(readback+4)) (void)readback_redirect(m,readback,m.read_u32(font+32),services);
        return 0;
    }
    case 0x1243e8:return finish_page(m,a3,services);
    case 0x123600: {
        const auto script=m.read_u32(manager(m)+0x38);
        // Retail175F78(30) always returns0; the source tail passes a2=0,a3=0.
        page_visit(m,script,sx(m.read_u32(script+0xd4)),0,0,services);return 0;
    }
    case 0x123558:return enter_wait(m,a1,services);
    case 0x10eca0:page_visit(m,self,a1,a2,a3,services);return 0;
    case 0x19cb50: {PageSourceCallbacks callbacks(services);choice_progress_label_transactional(m,self,callbacks);return 0;}
    case 0x1114f8:clear_page(m,self,services);return 0;
    case 0x16cb40:show_indicator(m,1);return 0;
    case 0x16cad0:show_indicator(m,0);return 0;
    case 0x16a998:line_advance(m,self);return 0;
    case 0x119eb0:return readback_redirect(m,self,a1,services);
    case 0x120030:case 0x11fe80:return wait_update(m,entry,u32(a1),services);
    case 0x1200f8:case 0x11fee8:return 1;
    case 0x120160:return wait_accept(m,m.read_u16(u32(a1)));
    case 0x122ef8:prepass09(m,services);return 0;
    case 0x123448:case 0x1231c0: {
        const auto owner=manager(m),redirect=m.read_u32(owner+0x2c);
        prepass09(m,services);
        if(m.read_u32(redirect))return 0;
        if(m.read_u32(owner+0x808))m.write_u32(owner+0x814,m.read_u32(owner+0x80c));
        m.write_u32(owner+0x40,u32(hot_context(m,0x235f34,0x11fe00,services)));
        show_indicator(m,0);return 1;
    }
    default:throw std::invalid_argument("Unrecovered page control source entry");
    }
}
}
