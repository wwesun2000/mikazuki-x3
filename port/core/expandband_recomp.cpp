#include "expandband_recomp.hpp"
#include "gradefilter.hpp"
#include "expandblur.hpp"
#include "screen_slide.hpp"
#include "screen_wind.hpp"
#include "screen_wipes.hpp"
#include "screen_zoom.hpp"
#include "screen_shake.hpp"
#include "field_feedback.hpp"
#include "masked_feedback.hpp"
#include "captured_blur.hpp"
#include "screen_ripple.hpp"
#include "depth_particles.hpp"
#include "visual_trig.hpp"
#include "session_clock.hpp"
#include "circlemask.hpp"
#include "ee_scalar.hpp"
#include "cue_effect.hpp"
#include "guest_memory.hpp"
#include <algorithm>
#include <bit>
#include <cmath>
#include <cstring>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace kx3 {
namespace {
using namespace ee;
constexpr u32 stack_base=0x1fff000,stack_top=stack_base+256;
constexpr u32 return_pc=0x3ff000,gs_context=0x70000100;
bool contains(u32 address,unsigned n,u32 base,unsigned size){
    return n<=size && address>=base && address-base<=size-n;
}
void check(bool ok,const char* msg){if(!ok)throw std::runtime_error(msg);}
[[noreturn]] void unexpected(u32 pc,u32 target,std::string_view why){
    std::ostringstream s;s<<"expandband 0x"<<std::hex<<pc<<" -> 0x"<<target<<" "<<why;throw std::runtime_error(s.str());
}
struct PS2Runtime {
    enum class GuestBranchKind {DirectCall,DirectJump,IndirectJump,Return};
    const GuestMemory& mem;
    GuestMemory* writable;
    u32 entry,heap=0,task=0,payload=0,field=0,draw_stage=0;
    bool freed=false;
    std::array<std::uint8_t,256> stack{};
    ExpandBandDraw draw{};
    GradeColors colors{};
    BlurDraw blur_draw{};
    SlideDraw slide_draw{};
    std::vector<WindSprite> wind_draw;
    std::vector<WipeSprite> wipe_draw;
    ZoomDraw zoom_draw{};
    ShakeDraw shake_draw{};
    FeedbackDraw feedback_draw;
    std::array<float,4> feedback_mask{};
    u32 feedback_bytes=400;
    u32 capture_bytes=32,capture_buffer=0,phase=0;
    bool capture_freed=false;
    u32 ripple_bytes=0x16000;
    std::vector<ZoomDraw> ripple_draw;
    u32 particle_bytes=0x16000,particle_light=128;
    std::vector<DepthParticleSprite> particle_draw;
    ExecutionServices* services=nullptr;
    CircleDraw circle_draw;
    unsigned circle_test=7,circle_depth=0,circle_palette=0;
    void circle_call(R5900Context*,u32 target,u32 pc);
    unsigned budget=32;
    bool eeCheckpointDue(){check(budget--!=0,"Effect exceeded its original bounded loops");return false;}
    void handleBreak(std::uint8_t*,R5900Context* c){unexpected(c->pc,0,"original effect BREAK");}
    bool grade()const{return entry>=0x1812a8 && entry<=0x1819b8;}
    bool blur()const{return entry>=0x182a08 && entry<=0x183240;}
    bool zoom()const{return entry>=0x182308 && entry<=0x1829f0;}
    bool shake()const{return entry>=0x181f90 && entry<=0x1822f0;}
    bool feedback()const{return entry>=0x17e570 && entry<=0x17ea98;}
    bool masked_feedback()const{return entry>=0x17f008 && entry<=0x17f658;}
    bool captured_blur()const{return entry>=0x17f670 && entry<=0x17fe98;}
    bool ripple()const{return entry>=0x1819d0 && entry<=0x181f78;}
    bool depth_particles()const{return entry>=0x183820 && entry<=0x1840a0;}
    bool brightness()const{return entry==0x135858 || entry==0x1358a8;}
    bool incoming_slide()const{return entry>=0x18aad8 && entry<=0x18b028;}
    bool outgoing_slide()const{return entry>=0x18a710 && entry<=0x18aac0;}
    bool slide()const{return outgoing_slide() || incoming_slide() || (entry>=0x18b040 && entry<=0x18b580);}
    bool circle()const{return entry>=0x193978 && entry<=0x1944a8;}
    bool wind()const{return entry>=0x18ef38 && entry<=0x18f718;}
    const ScreenWipe* wipe()const{return screen_wipe(entry);}
    bool screen()const{return slide() || circle() || wind() || wipe();}
    bool factory()const{
        if(const auto* w=wipe())return entry==w->factory;
        switch(entry){
        case 0x17e570:case 0x17f008:case 0x17f670:case 0x1812a8:case 0x1819d0:case 0x181f90:
        case 0x182308:case 0x1826b8:case 0x182a08:case 0x182aa0:case 0x183820:
        case 0x184690:case 0x18a710:case 0x18aad8:case 0x18b040:case 0x193978:case 0x18ef38:return true;
        default:return false;
        }
    }
    u32 payload_bytes()const{
        if(const auto* w=wipe())return w->bytes;
        if(wind())return 0x141c;
        if(circle())return 64;
        if(outgoing_slide() || incoming_slide())return 20;
        if(slide())return 28;
        if(captured_blur())return capture_bytes;
        if(depth_particles())return particle_bytes;
        if(ripple())return ripple_bytes;
        if(feedback() || masked_feedback())return feedback_bytes;
        if(shake())return 32;
        if(zoom())return 52;
        if(blur())return 388;
        return grade()?76:12;
    }

    void bind(u32 target){
        task=target;
        check(task>=0x240000 && (task&3)==0 && contains(task,48,0,stack_base),"Invalid expandband task");
        (void)mem.bytes(task,48);
    }
    void bind_existing(u32 target){
        bind(target);
        payload=mem.read_u32(task+44);
        check(payload>=0x240000 && (payload&3)==0 && contains(payload,payload_bytes(),0,stack_base) &&
              (payload+payload_bytes()<=task || task+48<=payload),"Invalid source effect payload");
        if(wind() || wipe())check(payload==wind_payload((task-mem.read_u32(0x2388bc))/48),"Mismatched original wipe work");
        if(captured_blur()){
            const auto count=mem.read_u32(payload),pool=mem.read_u32(0x2388bc);
            check(task>=pool+23*48 && task<=pool+32*48 && (task-pool)%48==0 && count>=1 && count<=13 &&
                  payload==letter_blur_payload((task-pool)/48-23),"Invalid letter-blur allocation");
            capture_bytes=12+4*count;capture_buffer=mem.read_u32(payload+8);
            check(capture_buffer==0x240000,"Invalid letter-blur field allocation");budget=400;
        }
        if(ripple()){
            const auto count=mem.read_u32(payload+4);
            check(count>=1 && count<=(0x16000-36)/8 && payload==large_effect_payload(mem,task,36+8*count),
                  "Invalid original ripple allocation");
            ripple_bytes=36+8*count;budget=2*count+128;
        }
        if(depth_particles()){
            const auto count=mem.read_u32(payload);
            check(count>=1 && count<=(0x16000-28)/36 && payload==large_effect_payload(mem,task,28+36*count),
                  "Invalid original depth-particle allocation");
            particle_bytes=28+36*count;budget=8*count+128;
        }
    }
    u64 read(u32 p,unsigned n)const {
        u64 value=0;
        if(captured_blur() && p==gs_context+4 && n==4)return phase;
        if(contains(p,n,stack_base,stack.size())){
            for(unsigned i=0;i<n;++i)value|=u64(stack[p-stack_base+i])<<(8*i);
            return value;
        }
        check((task && contains(p,n,task,48)) || (payload && contains(p,n,payload,payload_bytes())) ||
              (wipe()?(contains(p,n,0x237a20,0x2a0) || contains(p,n,0x22f2f0,64)):
               wind()?(contains(p,n,0x237bc8,0x58) || contains(p,n,0x237290,4)):
               circle()?(contains(p,n,0x237e58,32) || contains(p,n,0x23a4f0,8)):
               outgoing_slide()?(contains(p,n,0x237970,44) || contains(p,n,0x22f1cc,32)):
               incoming_slide()?(contains(p,n,0x23799c,36) || contains(p,n,0x22f204,64)):
               slide()?(contains(p,n,0x2379c0,64) || contains(p,n,0x22f260,32)):
               brightness()?(contains(p,n,0x206220,68) || contains(p,n,0x2062b4,4) || contains(p,n,0x2070f0,4)):
               depth_particles()?(contains(p,n,0x237594,112) || contains(p,n,0x237290,4)):
               captured_blur()?contains(p,n,0x2373fc,32):ripple()?contains(p,n,0x237480,48):masked_feedback()?contains(p,n,0x2373d8,36):feedback()?contains(p,n,0x2373bc,12):
               shake()?(contains(p,n,0x2374b0,12) || contains(p,n,0x237290,4)):
               zoom()?contains(p,n,0x2374bc,72):
               blur()?contains(p,n,0x237504,44):contains(p,n,grade()?0x237474:0x237640,grade()?12:16)),
              "Undeclared effect guest read");
        const auto b=mem.bytes(p,n);
        for(unsigned i=0;i<n;++i)value|=u64(b[i])<<(8*i);
        return value;
    }
    void write(u32 p,u64 value,unsigned n){
        std::array<std::uint8_t,8> b{};
        for(unsigned i=0;i<n;++i)b[i]=std::uint8_t(value>>(8*i));
        if(contains(p,n,stack_base,stack.size())){
            std::copy_n(b.begin(),n,stack.begin()+(p-stack_base));return;
        }
        check(writable && ((task && contains(p,n,task,48)) || (payload && contains(p,n,payload,payload_bytes()))),
              "Undeclared expandband guest write");
        writable->write_bytes(p,std::span(b).first(n));
    }
    void write_quad(u32 p,Quad value){
        check((p&15)==0 && contains(p,16,stack_base,stack.size()),"Unexpected expandband SQ destination");
        write(p,value.lo,8);write(p+8,value.hi,8);
    }
    std::array<u32,4> color(u32 p)const{
        check(contains(p,16,stack_base,stack.size()),"Invalid expandband RGBA pointer");
        return {u32(read(p,4)),u32(read(p+4,4)),u32(read(p+8,4)),u32(read(p+12,4))};
    }
    bool dispatchGuestBranch(std::uint8_t*,R5900Context*,u32,u32,u32,GuestBranchKind,const char*);
};

#define PS2_POR(a,b) (Quad{(a).lo|(b).lo,(a).hi|(b).hi})
#define READ32(p) u32(runtime->read(p,4))
#define FAST_READ32(p) READ32(p)
#define READ64(p) runtime->read(p,8)
#define WRITE32(p,v) runtime->write(p,u32(v),4)
#define WRITE64(p,v) runtime->write(p,u64(v),8)
#define WRITE128(p,v) runtime->write_quad(p,v)
#define PS2X_STRICT_RETURN_DIAGNOSTICS 1
#include "expandband_generated.hpp"
#define GPR_S32(c,n) std::bit_cast<i32>((c)->word(n))
#define FPU_CVT_W_S(a) static_cast<i32>(std::clamp(double(ordinary(a)),double(INT32_MIN),double(INT32_MAX)))
#include "gradefilter_generated.hpp"
#define GPR_S64(c,n) std::bit_cast<std::int64_t>((c)->r[n].lo)
#define SLL32(v,s) (u32(v)<<((s)&31))
#define SRL32(v,s) (u32(v)>>((s)&31))
#define FPU_C_OLE_S(a,b) (ordinary(a)<=ordinary(b))
#include "expandblur_generated.hpp"
#define FPU_NEG_S(a) (-ordinary(a))
#include "screen_slide_generated.hpp"
#define FPU_MUL_S(a,b) round_towards_zero(double(a)*double(b))
#include "wind_generated.hpp"
#define SUB32(a,b) (u32(a)-u32(b))
#include "screen_zoom_generated.hpp"
#include "screen_shake_generated.hpp"
#include "field_feedback_generated.hpp"
#include "masked_feedback_generated.hpp"
#include "captured_blur_generated.hpp"
#include "screen_ripple_generated.hpp"
#define FPU_SET_ACC(c,v) ((c)->f_acc=(v))
#define FPU_SQRT_S(v) std::sqrt(ordinary(v))
#define SET_GPR_S64(c,n,v) (c)->set64(n,u64(v))
#define SRA32(v,s) (std::bit_cast<i32>(u32(v))>>((s)&31))
#include "circlemask_generated.hpp"
#include "depth_particles_generated.hpp"
#include "screen_wipes_generated.hpp"
#undef PS2X_STRICT_RETURN_DIAGNOSTICS

void PS2Runtime::circle_call(R5900Context* c,u32 target,u32 pc){
    if(target==0x10b290){
        check(c->word(4)==3,"Unexpected circle mask texture slot");
        c->set32(2,0x23a480);return;
    }
    if(target==0x179fb8){
        const float z=c->f[12];
        check(z==0 || z==1 || z==10 || z==100,"Unexpected circle mask Z");
        circle_depth=unsigned(z);return;
    }
    check(c->word(4)==gs_context,"Unexpected circle GS context");
    switch(target){
    case 0x179de0:check(draw_stage++==0 && c->word(5)==0x1680,"Unexpected captured field");return;
    case 0x176970:check(draw_stage++==1 && c->word(5)==8000,"Unexpected current field");return;
    case 0x176c48:check(draw_stage++==2,"Unexpected GS reset");return;
    case 0x176638:{
        const u32 table=c->word(10);
        check(c->word(5)==((read(0x23a4f0,8)>>37)&0x3fff) && !c->word(6) && c->word(7)==16 &&
              c->word(8)==2 && !c->word(9) && table>=0x20d9f0 && table<=0x20e170+14*128 &&
              (table-0x20d9f0)%128==0,"Unexpected 193CB8 CLUT transfer");
        circle_palette=table;return;
    }
    case 0x176ac8:return; // TEXFLUSH; subsequent draws sample the most recently uploaded CLUT.
    case 0x176d98:circle_test=c->word(5);return;
    }
    CirclePass pass{};pass.test=circle_test;pass.depth=circle_depth;pass.palette=circle_palette;
    if(target==0x178910){
        check((c->word(5)==8000 || c->word(5)==0x1680) && !c->word(7) &&
              c->f[12]==0 && c->f[13]==0 && c->f[14]==639 && c->f[15]==223 &&
              c->f[16]==0 && c->f[17]==0 && c->f[18]==639 && c->f[19]==223,"Unexpected full-field sprite");
        pass.source=c->word(5)==8000?CircleSource::current:CircleSource::saved;
        const auto rgba=color(c->word(6));
        check(rgba[0]==128 && rgba[1]==128 && rgba[2]==128 && rgba[3]<=128,"Unexpected field modulation");
        pass.alpha=rgba[3];
    }else if(target==0x1769f0){
        check(c->word(5)==2 && c->word(6)==payload+32 && !c->word(8) &&
              color(c->word(7))==std::array<u32,4>{128,128,128,128},"Unexpected mask sprite ABI");
        const float x=std::bit_cast<float>(u32(read(payload+32,4))),y=std::bit_cast<float>(u32(read(payload+36,4)));
        pass.source=CircleSource::mask;pass.alpha=128;
        pass.xy={x,y*0.5f,ee_add_sub(x,c->f[12],false),ee_add_sub(y,c->f[13],false)*0.5f};
    }else if(target==0x178a10){
        check(color(c->word(5))==std::array<u32,4>{0,0,0,0} && c->f[12]==0 && c->f[13]==0 &&
              c->f[14]==640 && c->f[15]==448,"Unexpected circle clear");
        pass.source=CircleSource::solid;
    }else unexpected(pc,target,"unrecovered circle mask GS call");
    circle_draw.push_back(pass);
}

bool PS2Runtime::dispatchGuestBranch(std::uint8_t* ram,R5900Context* c,u32 target,u32 pc,u32 resume,
                                    GuestBranchKind kind,const char*){
    check(!c->in_delay_slot && c->pc==target,"Expandband transfer ran before its delay slot");
    if(kind==GuestBranchKind::Return)return false; // Checked by the calling frame against its saved resume PC.
    if(kind==GuestBranchKind::DirectJump){
        if((entry==0x18a890 || entry==0x18ad18 || entry==0x18b290 || entry==0x193bf0 || entry==0x18f230 || entry==0x18f370 || wipe()) && (target==0x10c368 || target==0x17a198) && writable){
            screen_transition_service(*writable,target,c->word(4));c->pc=c->word(31);return false;
        }
        if(target==0x179c68 && ((entry==0x1814c0 && pc==0x181600) || (entry==0x181858 && pc==0x181910) ||
                              (entry==0x182078 && pc==0x182160) || (entry==0x17e698 && pc==0x17e710) ||
                              (entry==0x17f1a8 && pc==0x17f220) || (entry==0x17f7f0 && pc==0x17f868))){
            FUN_00179c68_0x179c68(ram,c,this);return false;
        }
        if(target==0x179c40 && ((entry==0x182d58 && pc==0x182e64) || (entry==0x182f70 && pc==0x183070) ||
           (entry==0x1824c8 && pc==0x18259c) || (entry==0x182870 && pc==0x1828ec) || (entry==0x18f230 && pc==0x18f2e0) ||
           (entry==0x1900b0 && pc==0x190174))){
            FUN_00179c40_0x179c40(ram,c,this);return false;
        }
        if(!((wipe() && entry==wipe()->release && pc==entry+16) || (pc==0x18f728 && entry==0x18f718) || (pc==0x1848c8 && entry==0x1848b8) || (pc==0x1819c8 && entry==0x1819b8) ||
             (pc==0x183250 && entry==0x183240) || (pc==0x18b590 && entry==0x18b580) ||
             (pc==0x18aad0 && entry==0x18aac0) || (pc==0x18b038 && entry==0x18b028) ||
             (pc==0x17febc && entry==0x17fe98 && capture_freed) || (pc==0x17f668 && entry==0x17f658) || (pc==0x1840b0 && entry==0x1840a0) || (pc==0x181f88 && entry==0x181f78) || (pc==0x17eaa8 && entry==0x17ea98) || (pc==0x182300 && entry==0x1822f0) || (pc==0x1826b0 && entry==0x1826a0) || (pc==0x182a00 && entry==0x1829f0) || (pc==0x1944b8 && entry==0x1944a8)) ||
           target!=0x17a5f8 || c->word(4)!=payload)
            unexpected(pc,target,"unknown release");
        // Source frees its 12-byte allocation. Native mode-zero payloads are
        // reserved per scheduler slot and become reusable when its owner retires.
        freed=true;c->pc=c->word(31);return false;
    }
    if(kind!=GuestBranchKind::DirectCall || c->word(31)!=resume || resume!=pc+8)
        unexpected(pc,target,"unknown call ABI");
    auto nested=[&](auto body){
        body(ram,c,this);check(c->pc==resume,"Incorrect generated effect return PC");return true;
    };
    switch(target){
    case 0x18f108:return nested(FUN_0018f108_0x18f108);
    case 0x18f4d0:return nested(FUN_0018f4d0_0x18f4d0);
    case 0x17a8b0:check(entry==0x182078 || depth_particles() || wind(),"Unexpected effect RNG call");return nested(FUN_0017a8b0_0x17a8b0);
    case 0x1f0838:
        check(entry==0x181bc8,"Unexpected ripple sine call");
        c->f[0]=source_visual_sine(mem,c->f[12]);break;
    case 0x1f08f0:
        check(depth_particles(),"Unexpected particle tangent call");c->f[0]=source_visual_tangent(mem,c->f[12]);break;
    case 0x183968:check(depth_particles(),"Unexpected particle reset call");return nested(FUN_00183968_0x183968);
    case 0x135858:check(brightness(),"Unexpected sprite brightness read");return nested(FUN_00135858_0x135858);
    case 0x17a9c8:check(entry==0x182078 || depth_particles(),"Unexpected effect range call");return nested(FUN_0017a9c8_0x17a9c8);
    case 0x17a6e8:
        check((entry==0x182078 || depth_particles() || wind()) && writable,"Unexpected effect random-word call");
        c->set32(2,source_random_word(*writable,services));break;
    case 0x1769e0:
        check(entry==0x17f670,"Unexpected letter-blur field size query");c->set32(2,0x8c000);break;
    case 0x17a5f8:
        check(entry==0x17fe98 && c->word(4)==capture_buffer && !capture_freed,"Unexpected letter-blur field release");
        capture_freed=true;break;
    case 0x179b58:
        if(captured_blur()){
            check(entry==0x17f670 && !task && writable && c->word(4)==3,"Invalid letter-blur task request");
            const auto pool=mem.read_u32(0x2388bc);check(pool!=0,"Missing source task pool");
            // Original 179C14..20 selects slots 23..32. The admitted retail
            // cue ID is unique in each owner; reserve one live field buffer.
            for(unsigned i=23;i<=32;++i){const auto t=pool+48*i;
                check(!mem.read_u32(t) || mem.read_u32(t+24)!=0x17fe70,"Letter-blur field already owned");}
            for(unsigned i=23;i<=32;++i){const auto t=pool+48*i;if(mem.read_u32(t))continue;
                bind(t);for(unsigned off=0;off<48;off+=4)writable->write_u32(t+off,0);
                writable->write_u32(t,1);writable->write_u32(t+8,3);break;}
            check(task!=0,"179B58 mode-three task pool exhausted");c->set32(2,task);break;
        }
        check(factory() && !task && c->word(4)==(screen()?2u:0u) && writable,"Unexpected effect task allocation");
        bind(screen()?reserve_mode_two_task(*writable):reserve_mode_zero_task(*writable));c->set32(2,task);break;
    case 0x13d098:case 0x17a1a8:case 0x179c80:
        check((entry==0x18a890 || entry==0x18ad18 || entry==0x18b290 || entry==0x193bf0 || wind() || wipe()) && writable,"Unexpected screen update service");
        c->set32(2,screen_transition_service(*writable,target,c->word(4)));break;
    case 0x179c40:return nested(FUN_00179c40_0x179c40);
    case 0x179c48:return nested(FUN_00179c48_0x179c48);
    case 0x179c58:return nested(FUN_00179c58_0x179c58);
    case 0x179c50:return nested(FUN_00179c50_0x179c50);
    case 0x179c60:return nested(FUN_00179c60_0x179c60);
    case 0x179c68:return nested(FUN_00179c68_0x179c68);
    case 0x182ac8:return nested(FUN_00182ac8_0x182ac8);
    case 0x182cd8:return nested(FUN_00182cd8_0x182cd8);
    case 0x17a560:{
        if(captured_blur()){
            check(entry==0x17f670 && task && writable && c->word(5)==0x22ed50 && !c->word(7) && c->word(8)==13,
                  "Unexpected letter-blur allocation ABI");
            if(!payload){
                check(c->word(4)==capture_bytes && c->word(6)==0x61,"Invalid letter-blur payload request");
                payload=letter_blur_payload((task-mem.read_u32(0x2388bc))/48-23);c->set32(2,payload);
            }else{
                check(!capture_buffer && c->word(4)==0x8c000 && c->word(6)==99,"Invalid letter-blur field request");
                capture_buffer=0x240000;c->set32(2,capture_buffer);
            }
            break;
        }
        check(factory() && task && !payload && c->word(4)==payload_bytes() &&
              c->word(5)==(wipe()?wipe()->source_file:wind()?0x22f440:circle()?0x22f4d0:outgoing_slide()?0x22f1b8:incoming_slide()?0x22f1f0:slide()?0x22f248:
                           depth_particles()?0x22ee80:ripple()?0x22ede0:masked_feedback()?0x22ed30:feedback()?0x22ed00:shake()?0x22edf8:zoom()?(entry==0x182308?0x22ee18:0x22ee30):blur()?0x22ee48:grade()?0x22edc0:0x22eeb0) &&
              c->word(6)==(wipe()?wipe()->source_line:wind()?0x78:circle()?0x6c:outgoing_slide()?101:incoming_slide()?100:slide()?0x5f:
                           depth_particles()?0x94:ripple()?0x91:masked_feedback()?0x65:feedback()?0x5d:shake()?0x58:zoom()?(entry==0x182308?0x55:0x54):blur()?0xa2:grade()?0x61:0x5d) &&
              !c->word(7) && c->word(8)==13,"Unexpected effect allocation ABI");
        const auto pool=mem.read_u32(0x2388bc);
        const u32 slot=(task-pool)/48-(screen()?0:13);
        check(slot<10 && (ripple() || depth_particles() || (heap && !(heap&15) && contains(heap,0x200+10*64,0,stack_base))),"Invalid expandband heap");
        payload=(wind() || wipe())?wind_payload(slot):depth_particles()?large_effect_payload(mem,task,particle_bytes):ripple()?large_effect_payload(mem,task,ripple_bytes):circle()?circle_payload(heap,slot):slide()?heap+32*slot:blur() || feedback() || masked_feedback()?blur_payload(heap,slot):grade()?heap+0x500+80*slot:heap+0x200+64*slot;
        check(contains(payload,payload_bytes(),0,stack_base),"Effect allocation outside arena");
        (void)mem.bytes(payload,payload_bytes());c->set32(2,payload);break;
    }
    default:{
        if(wipe() && entry==wipe()->draw){
            check(c->word(4)==gs_context,"Unexpected wipe GS drawing context");
            if(target==0x179de0 && c->word(5)==0x1680){draw_stage|=1;break;}
            if(target==0x176970 && c->word(5)==8000){draw_stage|=2;break;}
            if(target==0x176c48 && draw_stage==3){draw_stage|=4;break;}
            const std::array<float,4> xy={c->f[12],c->f[13],c->f[14],c->f[15]};
            check(draw_stage==7,"Wipe draw preceded its texture uploads");
            if(target==0x178a10 && c->word(5)==0x20d9e0){
                check(xy==std::array<float,4>{0,0,640,448},"Unexpected wipe clear region");
                wipe_draw.push_back({WipeSprite::Source::clear,xy,{},128});break;
            }
            if(target!=0x178910 && target!=0x177f68)unexpected(pc,target,"unknown wipe primitive");
            const auto tbp=c->word(5)&0x3fff;
            const auto rgba=color(c->word(6));
            check((tbp==8000 || tbp==0x1680) && rgba[0]==128 && rgba[1]==128 && rgba[2]==128 &&
                  rgba[3]<=128 && !c->word(7),"Unexpected wipe texture or modulation");
            wipe_draw.push_back({tbp==8000?WipeSprite::Source::current:WipeSprite::Source::saved,
                                 xy,{c->f[16],c->f[17],c->f[18],c->f[19]},rgba[3]});
            break;
        }
        if(entry==0x18f3e8 && c->word(4)==gs_context){
            if(pc==0x18f420 && target==0x179de0 && !draw_stage && c->word(5)==0x1680){++draw_stage;break;}
            if(pc==0x18f428 && target==0x176c48 && draw_stage==1){++draw_stage;break;}
            const bool base=pc==0x18f4a0 && target==0x178910 && draw_stage==2 && c->word(5)==0x1680;
            const bool strip=(pc==0x18f678 || pc==0x18f6f8) && target==0x177f68 && draw_stage>=3 && c->r[5].lo==0x628029680ull;
            if(!(base || strip) || c->word(7))unexpected(pc,target,"unknown wind sprite");
            const auto rgba=color(c->word(6));
            check(rgba[0]==128 && rgba[1]==128 && rgba[2]==128 && rgba[3]<=128,"Unexpected wind modulation");
            wind_draw.push_back({{c->f[12],c->f[13],c->f[14],c->f[15]},{c->f[16],c->f[17],c->f[18],c->f[19]},rgba[3]});
            ++draw_stage;break;
        }
        if(entry==0x193cb8){circle_call(c,target,pc);break;}
        if(entry==0x17fe70){
            check(c->word(4)==gs_context,"Unexpected letter-blur GS context");
            if(!phase){
                if(target==0x17aee8 && draw_stage==0 && c->word(5)==capture_buffer){++draw_stage;break;}
                if(target==0x176c48 && draw_stage==1){++draw_stage;break;}
                if(target==0x176ea0 && draw_stage==2 && c->word(5)==1){++draw_stage;break;}
                if(target==0x176d98 && draw_stage==3 && c->word(5)==7){++draw_stage;break;}
                if(target==0x178a10 && draw_stage==4 && c->f[12]==0 && c->f[13]==0 && c->f[14]==640 && c->f[15]==448 &&
                   color(c->word(5))==std::array<u32,4>{0,0,0,0}){++draw_stage;break;}
                unexpected(pc,target,"Unrecovered letter-blur capture pass");
            }
            if(target==0x176c48 && draw_stage==0){++draw_stage;break;}
            if(target==0x176970 && draw_stage==1 && c->word(5)==0x1680){++draw_stage;break;}
            if(target==0x176818 && draw_stage==2 && c->word(5)==capture_buffer){++draw_stage;break;}
            if(target!=0x177f48 || draw_stage<3 || c->r[5].lo!=0x628029680ull || c->word(7)!=1)
                unexpected(pc,target,"Unrecovered original letter-blur sprite");
            const auto rgba=color(c->word(6));
            check(rgba[0]==128 && rgba[1]==128 && rgba[2]==128 && rgba[3]<=128,"Invalid letter-blur modulation");
            FeedbackSprite sprite;sprite.alpha=rgba[3];
            std::copy_n(c->f.begin()+12,4,sprite.coordinates.xy.begin());
            std::copy_n(c->f.begin()+16,4,sprite.coordinates.uv.begin());feedback_draw.push_back(sprite);++draw_stage;break;
        }
        if(entry==0x17f230){
            if(target==0x179fb8){
                const float expected=draw_stage==2?0.f:draw_stage==5?100.f:draw_stage==8?1.f:-1.f;
                check(expected>=0 && c->f[12]==expected,"Unverified focus-mask depth");++draw_stage;break;
            }
            check(c->word(4)==gs_context,"Unverified focus-mask GS context");
            if(target==0x175fa0 && !draw_stage){++draw_stage;c->set32(2,field);break;}
            if(target==0x176c48 && draw_stage==1){++draw_stage;break;}
            if(target==0x176d98){
                const auto count=u32(read(payload,4));
                const unsigned expected=draw_stage==3?6:draw_stage==6?2:draw_stage==9?5:draw_stage==10+5*count?7:UINT32_MAX;
                check(c->word(5)==expected,"Unverified focus-mask depth/alpha test");++draw_stage;break;
            }
            if(target==0x178a10 && draw_stage==4 && c->f[12]==0 && c->f[13]==0 && c->f[14]==640 && c->f[15]==448 &&
               color(c->word(5))==std::array<u32,4>{0,0,0,0}){++draw_stage;break;}
            if(target==0x1769f0 && draw_stage==7 && c->word(5)==2 && c->word(6)==payload+16 && !c->word(8) &&
               color(c->word(7))==std::array<u32,4>{128,128,128,128}){
                feedback_mask={std::bit_cast<float>(u32(read(payload+16,4))),std::bit_cast<float>(u32(read(payload+20,4))),c->f[12],c->f[13]};
                ++draw_stage;break;
            }
            if(target==0x176ac8 && draw_stage>=10 && (draw_stage-10)%5==0){++draw_stage;break;}
            if(target!=0x178910 || draw_stage<11 || (draw_stage-10)%5==0 || c->word(5)!=field*0x8c0 || c->word(7))
                unexpected(pc,target,"Unverified original masked-feedback pass");
            const auto rgba=color(c->word(6));
            check(rgba[0]==128 && rgba[1]==128 && rgba[2]==128 && rgba[3]<=128,"Unexpected focus-feedback modulation");
            FeedbackSprite sprite;sprite.alpha=rgba[3];
            std::copy_n(c->f.begin()+12,4,sprite.coordinates.xy.begin());
            std::copy_n(c->f.begin()+16,4,sprite.coordinates.uv.begin());feedback_draw.push_back(sprite);++draw_stage;break;
        }
        if(entry==0x183d30 && c->word(4)==gs_context){
            if(target==0x176c48 && !draw_stage){++draw_stage;break;}
            if(target!=0x1769f0 || !draw_stage || c->word(5) || c->word(8)!=1 || c->f[12]!=c->f[13])
                unexpected(pc,target,"Unverified original depth-particle sprite");
            const auto rgba=color(c->word(7));
            check(rgba[0]==128 && rgba[1]==128 && rgba[2]==128 && rgba[3]<=128,"Unexpected particle modulation");
            const auto position=c->word(6);
            const float x=std::bit_cast<float>(u32(read(position,4))),y=std::bit_cast<float>(u32(read(position+4,4)));
            particle_draw.push_back({x,y,c->f[12],rgba[3],particle_light});++draw_stage;break;
        }
        if(entry==0x181d98 && c->word(4)==gs_context){
            if(target==0x176970 && !draw_stage && c->word(5)==8000){++draw_stage;break;}
            if(target==0x176c48 && draw_stage==1){++draw_stage;break;}
            if(target==0x178a10 && draw_stage==2 && c->f[12]==0 && c->f[13]==0 && c->f[14]==640 && c->f[15]==448 &&
               color(c->word(5))==std::array<u32,4>{0,0,0,128}){++draw_stage;break;}
            if(target!=0x178910 || draw_stage<3 || c->word(5)!=8000 || c->word(7) ||
               color(c->word(6))!=std::array<u32,4>{128,128,128,128})unexpected(pc,target,"Unverified original ripple draw");
            ZoomDraw sprite;std::copy_n(c->f.begin()+12,4,sprite.xy.begin());
            std::copy_n(c->f.begin()+16,4,sprite.uv.begin());ripple_draw.push_back(sprite);++draw_stage;break;
        }
        if(entry==0x17e728 && c->word(4)==gs_context){
            if(target==0x175fa0 && !draw_stage){++draw_stage;c->set32(2,field);break;}
            if(target==0x176c48 && draw_stage==1){++draw_stage;break;}
            if(target==0x176ac8 && draw_stage>=2 && (draw_stage-2)%5==0){++draw_stage;break;}
            if(target!=0x178910 || draw_stage<3 || (draw_stage-2)%5==0 || c->word(5)!=field*0x8c0 || c->word(7))
                unexpected(pc,target,"Unverified original field-feedback pass");
            const auto rgba=color(c->word(6));
            check(rgba[0]==128 && rgba[1]==128 && rgba[2]==128 && rgba[3]<=128,"Unexpected feedback modulation");
            FeedbackSprite sprite;sprite.alpha=rgba[3];
            std::copy_n(c->f.begin()+12,4,sprite.coordinates.xy.begin());
            std::copy_n(c->f.begin()+16,4,sprite.coordinates.uv.begin());
            feedback_draw.push_back(sprite);++draw_stage;break;
        }
        if(entry==0x182188 && c->word(4)==gs_context){
            if(target==0x176970 && draw_stage==0 && c->word(5)==8000){++draw_stage;break;}
            if(target==0x176c48 && draw_stage==1){++draw_stage;break;}
            if(target!=0x178910 || draw_stage<2 || draw_stage>3 || c->word(5)!=8000 || c->word(7) ||
               color(c->word(6))!=std::array<u32,4>{128,128,128,draw_stage==2?128u:80u})
                unexpected(pc,target,"Unverified original camera shake draw");
            auto& sprite=shake_draw.sprites[draw_stage++-2];
            std::copy_n(c->f.begin()+12,4,sprite.xy.begin());std::copy_n(c->f.begin()+16,4,sprite.uv.begin());
            shake_draw.visible=true;break;
        }
        if((entry==0x1825b8 || entry==0x182908) && c->word(4)==gs_context){
            if(target==0x176970 && draw_stage==0 && c->word(5)==8000){++draw_stage;break;}
            if(target==0x176c48 && draw_stage==1){++draw_stage;break;}
            if(target==0x178a10 && draw_stage==2 && c->f[12]==0 && c->f[13]==0 &&
               c->f[14]==640 && c->f[15]==448 && color(c->word(5))==std::array<u32,4>{0,0,0,128}){
                ++draw_stage;break;
            }
            if(target!=0x178910 || draw_stage!=3 || c->word(5)!=8000 || c->word(7) ||
               color(c->word(6))!=std::array<u32,4>{128,128,128,128})
                unexpected(pc,target,"unverified original zoom draw");
            std::copy_n(c->f.begin()+12,4,zoom_draw.xy.begin());
            std::copy_n(c->f.begin()+16,4,zoom_draw.uv.begin());++draw_stage;break;
        }
        if((entry==0x18a9f0 || entry==0x18aef8 || entry==0x18b408) && c->word(4)==gs_context){
            if(target==0x179de0 && !draw_stage && c->word(5)==0x1680){++draw_stage;break;}
            if(!outgoing_slide() && target==0x176970 && draw_stage==1 && c->word(5)==8000){++draw_stage;break;}
            if(target==0x176c48 && draw_stage==(outgoing_slide()?1u:2u)){++draw_stage;break;}
            if(entry==0x18b408 && target==0x178a10 && draw_stage==3 && c->word(5)==0x20d9d0 &&
               c->f[12]==0 && c->f[13]==0 && c->f[14]==640 && c->f[15]==448){++draw_stage;break;}
            const unsigned first=outgoing_slide()?2:entry==0x18aef8?3:4;
            const auto texture=outgoing_slide()?0x1680u:entry==0x18aef8?(draw_stage==first?0x1680u:8000u):(draw_stage==first?8000u:0x1680u);
            if(target!=0x178910 || draw_stage<first || draw_stage>first+(outgoing_slide()?0:1) || c->word(7) ||
               c->word(5)!=texture || color(c->word(6))!=std::array<u32,4>{128,128,128,128} ||
               c->f[16]!=0 || c->f[17]!=0 || c->f[18]!=639 || c->f[19]!=223)unexpected(pc,target,"unknown screen slide draw");
            auto& xy=slide_draw[draw_stage++-first];std::copy_n(c->f.begin()+12,4,xy.begin());break;
        }
        if(entry==0x183088 && c->word(4)==gs_context){
            if(target==0x176970 && draw_stage==0 && c->word(5)==8000){++draw_stage;break;}
            if(target==0x176c48 && draw_stage==1){++draw_stage;break;}
            const std::array<float,4> xy{c->f[12],c->f[13],c->f[14],c->f[15]};
            if(target==0x178a10 && draw_stage==2 && xy==std::array<float,4>{0,0,640,448} &&
               color(c->word(5))==std::array<u32,4>{0,0,0,128}){++draw_stage;break;}
            if(target!=0x178910 || draw_stage<3 || draw_stage>=24 || c->word(5)!=8000 || c->word(7) ||
               xy!=std::array<float,4>{0,0,639,223})unexpected(pc,target,"unknown expand blur draw");
            const auto rgba=color(c->word(6));
            check(rgba[0]==128 && rgba[1]==128 && rgba[2]==128 && rgba[3]<=128,"Unexpected expand blur modulation");
            auto& sprite=blur_draw[draw_stage++-3];
            std::copy_n(c->f.begin()+16,4,sprite.uv.begin());sprite.alpha=rgba[3];break;
        }
        if(entry==0x181660 && c->word(4)==gs_context){
            if(target==0x176970 && draw_stage==0 && c->word(5)==8000){++draw_stage;break;}
            if(target==0x176c48 && draw_stage==1){++draw_stage;break;}
            if(target!=0x1787d0 || draw_stage!=2)unexpected(pc,target,"unrecovered grade filter draw call");
            constexpr std::array<float,8> vertices{0,0,640,0,640,224,0,224};
            for(unsigned i=0;i<8;++i)
                check(c->f[12+i]==vertices[i] && read(c->word(29)+8*i,4)==std::bit_cast<u32>(vertices[i]),
                      "Unexpected grade filter vertices or UV");
            check(c->r[5].lo==0x628029f40ull && !c->word(10) && c->word(6)==c->word(7) &&
                  c->word(8)==c->word(9),"Unexpected grade filter texture or color arrays");
            colors.top=color(c->word(6));colors.bottom=color(c->word(8));++draw_stage;break;
        }
        if(entry!=0x1847a8 || c->word(4)!=gs_context)unexpected(pc,target,"unknown leaf");
        switch(target){
        case 0x175fa0:
            check(draw_stage++==0,"Unexpected expandband GS page query");c->set32(2,field);break;
        case 0x176c48:
            check(draw_stage++==1,"Unexpected expandband GS setup");break;
        case 0x177fa8:
            check(draw_stage==2 && !draw.black_strip,"Unexpected expandband black strip");
            draw.black_strip=true;std::copy_n(c->f.begin()+12,4,draw.black_xy.begin());
            draw.black_rgba=color(c->word(5));break;
        case 0x176ac8:
            check(draw_stage++==2,"Unexpected expandband sprite setup");break;
        case 0x178910:
            check(draw_stage++==3,"Unexpected expandband textured sprite");
            std::copy_n(c->f.begin()+12,4,draw.xy.begin());
            std::copy_n(c->f.begin()+16,4,draw.uv.begin());
            draw.texture_base=c->word(5);draw.rgba=color(c->word(6));draw.flags=c->word(7);break;
        default:unexpected(pc,target,"unrecovered draw leaf");
        }
    }}
    c->pc=resume;return true;
}

using Function=void(*)(std::uint8_t*,R5900Context*,PS2Runtime*);
Function wipe_function(u32 entry){
    switch(entry){
#define KX3_WIPE_ENTRY(pc,body) case pc:return body;
#include "screen_wipe_entries.hpp"
#undef KX3_WIPE_ENTRY
    default:throw std::runtime_error("Missing retail screen wipe function");
    }
}
u32 execute_args(PS2Runtime& runtime,Function function,std::span<const u32> args){
    R5900Context c;
    check(args.size()<=8,"Too many EE register arguments");
    for(unsigned i=0;i<args.size();++i)c.set32(4+i,args[i]);
    c.set32(29,stack_top);c.set32(31,return_pc);
    c.pc=runtime.entry;function(nullptr,&c,&runtime);
    check(c.pc==return_pc && !c.in_delay_slot && c.word(29)==stack_top,"Expandband callback failed to return");
    return c.word(2);
}
u32 execute(PS2Runtime& runtime,Function function,u32 a0,u32 a1=0){
    return execute_args(runtime,function,std::array{a0,a1});
}
template<class F> auto transact(GuestMemory& m,F run){
    if(m.transaction_active())return run();
    GuestMemory::Transaction tx(m);auto result=run();tx.commit();return result;
}
}

std::optional<std::uint32_t> original_background_darkening(const GuestMemory& m){
    // 1352F4/1352FC and 1353B8..1353D8. Without a fresh background
    // draw, the presenter keeps the previously rendered background.
    if(!m.read_u32(0x206810) || (m.read_u32(0x235fbc) && !m.read_u32(0x2062a8)))return {};
    PS2Runtime light{m,nullptr,0x135858};
    const auto fix=execute(light,FUN_00135858_0x135858,0);
    check(fix<=128,"Original background blend is out of range");
    return fix;
}

std::uint32_t create_expandband(GuestMemory& m,u32 heap,u32 interval){
    return transact(m,[&]{
        PS2Runtime runtime{m,&m,0x184690,heap};
        const auto result=execute(runtime,FUN_00184690_0x184690,interval);
        check(result && result==runtime.task && m.read_u32(result+44)==runtime.payload,"Incomplete expandband construction");
        return result;
    });
}
void update_expandband(GuestMemory& m,u32 task){
    transact(m,[&]{
        PS2Runtime runtime{m,&m,0x184760};runtime.bind_existing(task);
        return execute(runtime,FUN_00184760_0x184760,task);
    });
}
void release_expandband(GuestMemory& m,u32 task){
    PS2Runtime runtime{m,&m,0x1848b8};runtime.bind_existing(task);
    execute(runtime,FUN_001848b8_0x1848b8,task);
    check(runtime.freed,"Expandband cleanup did not release its allocation");
}
ExpandBandDraw draw_expandband(const GuestMemory& m,u32 task,unsigned physical_field){
    check(physical_field<2,"Invalid expandband GS page");
    PS2Runtime runtime{m,nullptr,0x1847a8};runtime.field=physical_field;runtime.bind_existing(task);
    execute(runtime,FUN_001847a8_0x1847a8,task,gs_context);
    check(runtime.draw_stage==4,"Incomplete expandband draw packet");return runtime.draw;
}
u32 create_gradefilter(GuestMemory& m,u32 heap,std::span<const u32> args){
    check(args.size()==7,"1812A8 expects seven parameters");
    return transact(m,[&]{
        PS2Runtime runtime{m,&m,0x1812a8,heap};
        const auto task=execute_args(runtime,FUN_001812a8_0x1812a8,args);
        check(task && task==runtime.task && m.read_u32(task+44)==runtime.payload,"Incomplete grade filter construction");
        return task;
    });
}
void update_gradefilter(GuestMemory& m,u32 task){
    transact(m,[&]{
        PS2Runtime runtime{m,&m,0x1814c0};runtime.bind_existing(task);
        return execute(runtime,FUN_001814c0_0x1814c0,task);
    });
}
void change_gradefilter(GuestMemory& m,u32 task,std::span<const u32> args){
    check(args.size()==7,"181858 expects seven source parameters");
    transact(m,[&]{
        PS2Runtime runtime{m,&m,0x181858};runtime.bind_existing(task);
        for(unsigned i=0;i<args.size();++i)runtime.write(stack_base+4*i,args[i],4);
        return execute_args(runtime,FUN_00181858_0x181858,std::array{task,1000u,7u,stack_base});
    });
}
void release_gradefilter(GuestMemory& m,u32 task){
    PS2Runtime runtime{m,&m,0x1819b8};runtime.bind_existing(task);
    execute(runtime,FUN_001819b8_0x1819b8,task);
    check(runtime.freed,"Grade filter cleanup did not release its allocation");
}
GradeColors draw_gradefilter(const GuestMemory& m,u32 task){
    PS2Runtime runtime{m,nullptr,0x181660};runtime.bind_existing(task);
    execute(runtime,FUN_00181660_0x181660,task,gs_context);
    check(runtime.draw_stage==3,"Incomplete grade filter command stream");return runtime.colors;
}
u32 create_expandblur(GuestMemory& m,u32 heap,u32 factory,std::span<const u32> args){
    check((factory==0x182a08 && args.size()==7) || (factory==0x182aa0 && args.size()==5),
          "Unexpected expand blur constructor ABI");
    return transact(m,[&]{
        PS2Runtime runtime{m,&m,factory,heap};
        const auto task=execute_args(runtime,factory==0x182a08?FUN_00182a08_0x182a08:FUN_00182aa0_0x182aa0,args);
        check(task && task==runtime.task && m.read_u32(task+44)==runtime.payload,"Incomplete expand blur construction");
        return task;
    });
}
void update_expandblur(GuestMemory& m,u32 task,u32 callback){
    Function entry=nullptr;
    switch(callback){
    case 0x182d58:entry=FUN_00182d58_0x182d58;break;
    case 0x182e90:entry=FUN_00182e90_0x182e90;break;
    case 0x182f70:entry=FUN_00182f70_0x182f70;break;
    default:throw std::invalid_argument("Unknown expand blur update callback");
    }
    transact(m,[&]{PS2Runtime runtime{m,&m,callback};runtime.bind_existing(task);return execute(runtime,entry,task);});
}
void release_expandblur(GuestMemory& m,u32 task){
    PS2Runtime runtime{m,&m,0x183240};runtime.bind_existing(task);
    execute(runtime,FUN_00183240_0x183240,task);check(runtime.freed,"Incomplete expand blur cleanup");
}
BlurDraw draw_expandblur(const GuestMemory& m,u32 task){
    PS2Runtime runtime{m,nullptr,0x183088};runtime.bind_existing(task);
    execute(runtime,FUN_00183088_0x183088,task,gs_context);
    check(runtime.draw_stage==24,"Incomplete expand blur GS packet");return runtime.blur_draw;
}
u32 create_captured_blur(GuestMemory& m,std::span<const u32> args){
    check(args.size()==2 && args[1]>=1 && args[1]<=13,"17F670 letter rings exceed reserved payload");
    return transact(m,[&]{PS2Runtime runtime{m,&m,0x17f670};runtime.capture_bytes=12+4*args[1];runtime.budget=400;
        const auto task=execute_args(runtime,FUN_0017f670_0x17f670,args);
        check(task==runtime.task && m.read_u32(task+44)==runtime.payload && runtime.capture_buffer==0x240000,
              "Incomplete letter-blur constructor");return task;});
}
void update_captured_blur(GuestMemory& m,u32 task){
    transact(m,[&]{PS2Runtime runtime{m,&m,0x17f7f0};runtime.bind_existing(task);
        return execute(runtime,FUN_0017f7f0_0x17f7f0,task);});
}
void release_captured_blur(GuestMemory& m,u32 task){
    PS2Runtime runtime{m,&m,0x17fe98};runtime.bind_existing(task);
    execute(runtime,FUN_0017fe98_0x17fe98,task);check(runtime.freed && runtime.capture_freed,"Incomplete letter-blur release");
}
FeedbackDraw draw_captured_blur(const GuestMemory& m,u32 task,unsigned phase){
    check(phase<2,"Invalid original letter-blur draw phase");
    PS2Runtime runtime{m,nullptr,0x17fe70};runtime.phase=phase;runtime.bind_existing(task);
    execute(runtime,FUN_0017fe70_0x17fe70,task,gs_context);
    const auto count=m.read_u32(runtime.payload);
    check(runtime.draw_stage==(phase?4+4*count:5),"Incomplete letter-blur draw sequence");
    return std::move(runtime.feedback_draw);
}
u32 create_masked_feedback(GuestMemory& m,u32 heap,std::span<const u32> args){
    check(args.size()==5 && args[1]>=1 && args[1]<=(400-48)/4,"17F008 rings exceed reserved effect slot");
    return transact(m,[&]{PS2Runtime runtime{m,&m,0x17f008,heap};runtime.feedback_bytes=48+4*args[1];runtime.budget=400;
        const auto task=execute_args(runtime,FUN_0017f008_0x17f008,args);
        check(task && task==runtime.task && m.read_u32(task+44)==runtime.payload,"Incomplete masked-feedback construction");return task;});
}
void update_masked_feedback(GuestMemory& m,u32 task){
    transact(m,[&]{PS2Runtime runtime{m,&m,0x17f1a8};runtime.budget=400;runtime.bind_existing(task);
        return execute(runtime,FUN_0017f1a8_0x17f1a8,task);});
}
void release_masked_feedback(GuestMemory& m,u32 task){
    PS2Runtime runtime{m,&m,0x17f658};runtime.bind_existing(task);
    execute(runtime,FUN_0017f658_0x17f658,task);check(runtime.freed,"Incomplete masked-feedback cleanup");
}
MaskedFeedbackDraw draw_masked_feedback(const GuestMemory& m,u32 task,unsigned field){
    check(field<2,"Invalid masked-feedback field");
    PS2Runtime runtime{m,nullptr,0x17f230};runtime.field=field;runtime.budget=400;runtime.bind_existing(task);
    const auto count=m.read_u32(runtime.payload);check(count<=(400-48)/4,"Invalid masked-feedback ring count");
    execute(runtime,FUN_0017f230_0x17f230,task,gs_context);
    check(runtime.draw_stage==11+5*count && runtime.feedback_draw.size()==4*count,"Incomplete masked-feedback draw stream");
    return {runtime.feedback_mask,std::move(runtime.feedback_draw)};
}
u32 create_depth_particles(GuestMemory& m,std::span<const u32> args,ExecutionServices* services){
    check(args.size()==4 && args[0]>=1 && args[0]<=(0x16000-28)/36,"183820 particles exceed reserved effect storage");
    return transact(m,[&]{PS2Runtime runtime{m,&m,0x183820};runtime.services=services;
        runtime.particle_bytes=28+36*args[0];runtime.budget=8*args[0]+128;
        const auto task=execute_args(runtime,FUN_00183820_0x183820,args);
        check(task && task==runtime.task && m.read_u32(task+44)==runtime.payload,"Incomplete depth-particle construction");return task;});
}
void update_depth_particles(GuestMemory& m,u32 task,ExecutionServices* services){
    transact(m,[&]{PS2Runtime runtime{m,&m,0x183b10};runtime.services=services;runtime.bind_existing(task);
        return execute(runtime,FUN_00183b10_0x183b10,task);});
}
void release_depth_particles(GuestMemory& m,u32 task){
    PS2Runtime runtime{m,&m,0x1840a0};runtime.bind_existing(task);
    execute(runtime,FUN_001840a0_0x1840a0,task);check(runtime.freed,"Incomplete depth-particle cleanup");
}
std::vector<DepthParticleSprite> draw_depth_particles(const GuestMemory& m,u32 task){
    PS2Runtime light{m,nullptr,0x1358a8};const auto brightness=execute(light,FUN_001358a8_0x1358a8,0);
    check(brightness<=255,"Original sprite brightness exceeds packed color byte");
    PS2Runtime runtime{m,nullptr,0x183d30};runtime.bind_existing(task);runtime.particle_light=brightness;
    execute(runtime,FUN_00183d30_0x183d30,task,gs_context);
    check(runtime.draw_stage==1+runtime.particle_draw.size() && runtime.particle_draw.size()<=m.read_u32(runtime.payload),
          "Incomplete original depth-particle drawing");return runtime.particle_draw;
}
u32 create_screen_ripple(GuestMemory& m,std::span<const u32> args){
    check(args.size()==3 && args[1]>=1 && args[1]<=(0x16000-36)/8,"1819D0 strips exceed reserved effect storage");
    return transact(m,[&]{PS2Runtime runtime{m,&m,0x1819d0};runtime.ripple_bytes=36+8*args[1];runtime.budget=2*args[1]+128;
        const auto task=execute_args(runtime,FUN_001819d0_0x1819d0,args);
        check(task && task==runtime.task && m.read_u32(task+44)==runtime.payload,"Incomplete ripple construction");return task;});
}
void update_screen_ripple(GuestMemory& m,u32 task){
    transact(m,[&]{PS2Runtime runtime{m,&m,0x181bc8};runtime.bind_existing(task);return execute(runtime,FUN_00181bc8_0x181bc8,task);});
}
void release_screen_ripple(GuestMemory& m,u32 task){
    PS2Runtime runtime{m,&m,0x181f78};runtime.bind_existing(task);
    execute(runtime,FUN_00181f78_0x181f78,task);check(runtime.freed,"Incomplete ripple cleanup");
}
std::vector<ZoomDraw> draw_screen_ripple(const GuestMemory& m,u32 task){
    PS2Runtime runtime{m,nullptr,0x181d98};runtime.bind_existing(task);
    execute(runtime,FUN_00181d98_0x181d98,task,gs_context);
    check(runtime.draw_stage==3+m.read_u32(runtime.payload+4),"Incomplete ripple draw stream");return runtime.ripple_draw;
}
u32 create_field_feedback(GuestMemory& m,u32 heap,std::span<const u32> args){
    check(args.size()==2 && args[1]>=1 && args[1]<=98,"17E570 ring count exceeds reserved 400-byte effect slot");
    return transact(m,[&]{PS2Runtime runtime{m,&m,0x17e570,heap};runtime.feedback_bytes=8+4*args[1];runtime.budget=400;
        const auto task=execute_args(runtime,FUN_0017e570_0x17e570,args);
        check(task && task==runtime.task && m.read_u32(task+44)==runtime.payload,"Incomplete field-feedback construction");
        return task;
    });
}
void update_field_feedback(GuestMemory& m,u32 task){
    transact(m,[&]{PS2Runtime runtime{m,&m,0x17e698};runtime.budget=400;runtime.bind_existing(task);
        return execute(runtime,FUN_0017e698_0x17e698,task);});
}
void release_field_feedback(GuestMemory& m,u32 task){
    PS2Runtime runtime{m,&m,0x17ea98};runtime.bind_existing(task);
    execute(runtime,FUN_0017ea98_0x17ea98,task);check(runtime.freed,"Incomplete field-feedback cleanup");
}
FeedbackDraw draw_field_feedback(const GuestMemory& m,u32 task,unsigned field){
    check(field<2,"Invalid field-feedback page");
    PS2Runtime runtime{m,nullptr,0x17e728};runtime.field=field;runtime.budget=400;runtime.bind_existing(task);
    const auto count=m.read_u32(runtime.payload);check(count<=98,"Unsupported feedback ring count");
    execute(runtime,FUN_0017e728_0x17e728,task,gs_context);
    check(runtime.draw_stage==2+5*count && runtime.feedback_draw.size()==4*count,"Incomplete field-feedback draw stream");
    return runtime.feedback_draw;
}
u32 create_screen_shake(GuestMemory& m,u32 heap,std::span<const u32> args){
    check(args.size()==3,"181F90 expects three source arguments");
    return transact(m,[&]{PS2Runtime runtime{m,&m,0x181f90,heap};
        const auto task=execute_args(runtime,FUN_00181f90_0x181f90,args);
        check(task && task==runtime.task && m.read_u32(task+44)==runtime.payload,"Incomplete shake construction");
        return task;
    });
}
void update_screen_shake(GuestMemory& m,u32 task,ExecutionServices* services){
    transact(m,[&]{PS2Runtime runtime{m,&m,0x182078};runtime.services=services;runtime.bind_existing(task);
        return execute(runtime,FUN_00182078_0x182078,task);});
}
void release_screen_shake(GuestMemory& m,u32 task){
    PS2Runtime runtime{m,&m,0x1822f0};runtime.bind_existing(task);
    execute(runtime,FUN_001822f0_0x1822f0,task);check(runtime.freed,"Incomplete shake cleanup");
}
ShakeDraw draw_screen_shake(const GuestMemory& m,u32 task){
    PS2Runtime runtime{m,nullptr,0x182188};runtime.bind_existing(task);
    execute(runtime,FUN_00182188_0x182188,task,gs_context);
    check(runtime.draw_stage==0 || runtime.draw_stage==4,"Incomplete shake draw");return runtime.shake_draw;
}
u32 create_screen_zoom(GuestMemory& m,u32 heap,u32 factory,std::span<const u32> args){
    check((factory==0x182308 && args.size()==5) || (factory==0x1826b8 && args.size()==2),
          "Unsupported original zoom parameters");
    return transact(m,[&]{
        PS2Runtime runtime{m,&m,factory,heap};
        const auto task=execute_args(runtime,factory==0x182308?FUN_00182308_0x182308:FUN_001826b8_0x1826b8,args);
        check(task && runtime.task==task && m.read_u32(task+44)==runtime.payload,"Incomplete zoom construction");
        return task;
    });
}
void update_screen_zoom(GuestMemory& m,u32 task,u32 callback){
    check(callback==0x1824c8 || callback==0x182870,"Unknown zoom update");
    transact(m,[&]{PS2Runtime runtime{m,&m,callback};runtime.bind_existing(task);
        return execute(runtime,callback==0x1824c8?FUN_001824c8_0x1824c8:FUN_00182870_0x182870,task);});
}
void release_screen_zoom(GuestMemory& m,u32 task){
    const auto entry=m.read_u32(task+32);
    check(entry==0x1826a0 || entry==0x1829f0,"Unknown zoom cleanup");
    PS2Runtime runtime{m,&m,entry};runtime.bind_existing(task);
    execute(runtime,entry==0x1826a0?FUN_001826a0_0x1826a0:FUN_001829f0_0x1829f0,task);
    check(runtime.freed,"Incomplete zoom cleanup");
}
ZoomDraw draw_screen_zoom(const GuestMemory& m,u32 task){
    const auto entry=m.read_u32(task+24);
    check(entry==0x1825b8 || entry==0x182908,"Unknown zoom draw");
    PS2Runtime runtime{m,nullptr,entry};runtime.bind_existing(task);
    execute(runtime,entry==0x1825b8?FUN_001825b8_0x1825b8:FUN_00182908_0x182908,task,gs_context);
    check(runtime.draw_stage==4,"Incomplete zoom draw stream");
    return runtime.zoom_draw;
}
u32 create_screen_slide(GuestMemory& m,u32 heap,std::span<const u32> args,u32 factory){
    check(args.size()==2,"18B040 expects two source arguments");
    check(factory==0x18a710 || factory==0x18aad8 || factory==0x18b040,"Unknown screen slide constructor");
    return transact(m,[&]{
        PS2Runtime runtime{m,&m,factory,heap};
        const auto result=execute_args(runtime,factory==0x18a710?FUN_0018a710_0x18a710:factory==0x18aad8?FUN_0018aad8_0x18aad8:FUN_0018b040_0x18b040,args);
        check(result && runtime.task==result && m.read_u32(result+44)==runtime.payload,"Incomplete slide construction");
        return result;
    });
}
void update_screen_slide(GuestMemory& m,u32 task){
    const auto entry=m.read_u32(task+20);
    check(entry==0x18a890 || entry==0x18ad18 || entry==0x18b290,"Invalid slide update callback");
    transact(m,[&]{PS2Runtime runtime{m,&m,entry};runtime.bind_existing(task);
        return execute(runtime,entry==0x18a890?FUN_0018a890_0x18a890:entry==0x18ad18?FUN_0018ad18_0x18ad18:FUN_0018b290_0x18b290,task);});
}
void release_screen_slide(GuestMemory& m,u32 task){
    const auto entry=m.read_u32(task+32);
    check(entry==0x18aac0 || entry==0x18b028 || entry==0x18b580,"Invalid slide cleanup callback");
    PS2Runtime runtime{m,&m,entry};runtime.bind_existing(task);
    execute(runtime,entry==0x18aac0?FUN_0018aac0_0x18aac0:entry==0x18b028?FUN_0018b028_0x18b028:FUN_0018b580_0x18b580,task);
    check(runtime.freed,"Incomplete screen slide cleanup");
}
SlideDraw draw_screen_slide(const GuestMemory& m,u32 task){
    const auto entry=m.read_u32(task+24);
    check(entry==0x18a9f0 || entry==0x18aef8 || entry==0x18b408,"Invalid slide draw callback");
    PS2Runtime runtime{m,nullptr,entry};runtime.bind_existing(task);
    execute(runtime,entry==0x18a9f0?FUN_0018a9f0_0x18a9f0:entry==0x18aef8?FUN_0018aef8_0x18aef8:FUN_0018b408_0x18b408,task,gs_context);
    check(runtime.draw_stage==(entry==0x18a9f0?3u:entry==0x18aef8?5u:6u),"Incomplete screen slide draw");
    return runtime.slide_draw;
}
u32 create_circlemask(GuestMemory& m,u32 heap,std::span<const u32> args){
    check(args.size()==5 && args[4]>=8 && args[4]<=10,"Unverified 193978 circle mode or arguments");
    return transact(m,[&]{PS2Runtime r{m,&m,0x193978,heap};
        const auto task=execute_args(r,FUN_00193978_0x193978,args);
        check(task && task==r.task && m.read_u32(task+44)==r.payload,"Incomplete circle constructor");return task;});
}
u32 create_screen_wind(GuestMemory& m,u32 heap,std::span<const u32> args){
    check(args.size()==2,"Unexpected 18EF38 wind arguments");
    return transact(m,[&]{
        PS2Runtime r{m,&m,0x18ef38,heap};r.budget=4096;
        const auto task=execute_args(r,FUN_0018ef38_0x18ef38,args);
        check(task && task==r.task && m.read_u32(task+44)==r.payload,"Incomplete wind constructor");
        return task;
    });
}
u32 create_screen_wipe(GuestMemory& m,u32 heap,std::span<const u32> args,const ScreenWipe& wipe){
    return transact(m,[&]{
        PS2Runtime r{m,&m,wipe.factory,heap};r.budget=4096;
        const auto task=execute_args(r,wipe_function(wipe.factory),args);
        check(task && task==r.task && m.read_u32(task+44)==r.payload &&
              m.read_u32(task+20)==wipe.update && m.read_u32(task+24)==wipe.draw &&
              m.read_u32(task+32)==wipe.release,"Incomplete original screen wipe registration");
        return task;
    });
}
void advance_screen_wipe(GuestMemory& m,u32 task,u32 pc){
    transact(m,[&]{
        PS2Runtime r{m,&m,pc};r.bind_existing(task);r.budget=8192;
        const auto result=execute(r,wipe_function(pc),task);
        if(pc==r.wipe()->release)check(r.freed,"Incomplete original wipe cleanup");
        return result;
    });
}
std::vector<WipeSprite> draw_screen_wipe(const GuestMemory& m,u32 task){
    const auto pc=m.read_u32(task+24);
    PS2Runtime r{m,nullptr,pc};r.bind_existing(task);r.budget=640*224*3+4096;
    execute(r,wipe_function(pc),task,gs_context);
    check(r.draw_stage==7,"Incomplete screen wipe texture setup");
    return std::move(r.wipe_draw);
}
void update_screen_wind(GuestMemory& m,u32 task){
    const auto entry=m.read_u32(task+20);
    check(entry==0x18f230 || entry==0x18f370,"Invalid wind update callback");
    transact(m,[&]{
        PS2Runtime r{m,&m,entry};r.bind_existing(task);r.budget=8192;
        return execute(r,entry==0x18f230?FUN_0018f230_0x18f230:FUN_0018f370_0x18f370,task);
    });
}
void release_screen_wind(GuestMemory& m,u32 task){
    PS2Runtime r{m,&m,0x18f718};r.bind_existing(task);execute(r,FUN_0018f718_0x18f718,task);
    check(r.freed,"Incomplete original wind cleanup");
}
std::vector<WindSprite> draw_screen_wind(const GuestMemory& m,u32 task){
    PS2Runtime r{m,nullptr,0x18f3e8};r.bind_existing(task);r.budget=8192;
    execute(r,FUN_0018f3e8_0x18f3e8,task,gs_context);
    const auto mode=m.read_u32(r.payload);
    check(r.wind_draw.size()==1+(mode<2?224u:mode<4?640u:0u),"Incomplete wind sprite list");
    return std::move(r.wind_draw);
}
void update_circlemask(GuestMemory& m,u32 task){
    transact(m,[&]{PS2Runtime r{m,&m,0x193bf0};r.bind_existing(task);return execute(r,FUN_00193bf0_0x193bf0,task);});
}
void release_circlemask(GuestMemory& m,u32 task){
    PS2Runtime r{m,&m,0x1944a8};r.bind_existing(task);execute(r,FUN_001944a8_0x1944a8,task);
    check(r.freed,"Incomplete circle cleanup");
}
CircleDraw draw_circlemask(const GuestMemory& m,u32 task){
    PS2Runtime r{m,nullptr,0x193cb8};r.bind_existing(task);execute(r,FUN_00193cb8_0x193cb8,task,gs_context);
    const auto mode=m.read_u32(m.read_u32(task+44));
    check(r.draw_stage==3 && r.circle_draw.size()==(mode==10?46u:4u),"Incomplete circle pass sequence");
    return std::move(r.circle_draw);
}
}
