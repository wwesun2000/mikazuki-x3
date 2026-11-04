#include "screen_mesh.hpp"
#include "screen_mesh_math.hpp"
#include "screen_mesh_double.hpp"
#include "screen_slide.hpp"
#include "visual_trig.hpp"
#include "session_clock.hpp"
#include <algorithm>
#include <cstring>
#include <sstream>
namespace kx3::screen_mesh {
namespace {
using namespace ee;
constexpr u32 stack_base=0x1fff000,stack_top=stack_base+1024,return_pc=0x3ff000;
constexpr u32 gs_context=0x70000100,queue=0x70000200,packet_base=0x70001000;
bool contains(u32 p,unsigned n,u32 base,unsigned size){return n<=size && p>=base && p-base<=size-n;}
void check(bool v,const char* reason){if(!v)throw std::runtime_error(reason);}
[[noreturn]] void fail(u32 pc,u32 target,const char* reason){std::ostringstream s;s<<"crash-wipe "<<std::hex<<pc<<" -> "<<target<<" "<<reason;throw std::runtime_error(s.str());}
struct PS2Runtime {
 enum class GuestBranchKind {DirectCall,DirectJump,IndirectJump,Return};
 const GuestMemory& mem;GuestMemory* writable;u32 entry,task=0,payload=0,bytes=0,stage=0;
 ExecutionServices* services=nullptr;bool freed=false,packet_live=false,matrix_loaded=false;
 std::array<std::uint8_t,1024> stack{};std::array<std::uint8_t,176> packet{};
 Matrix vu=identity();std::vector<Triangle> triangles;unsigned budget=20000;
 bool eeCheckpointDue(){check(budget--!=0,"Crash-wipe exceeded original bounded loops");return false;}
 void handleBreak(std::uint8_t*,R5900Context* c){fail(c->pc,0,"Original BREAK");}
 void bind(u32 t,bool existing){
  const auto pool=mem.read_u32(0x2388bc);check(pool && t>=pool && (t-pool)%48==0 && (t-pool)/48<10,"Invalid crash-wipe mode-two task");task=t;
  if(existing){payload=mem.read_u32(t+44);check(payload==mesh_begin+(t-pool)/48*mesh_stride,"Mismatched crash-wipe work");
   const auto count=mem.read_u32(payload+68);check(count==192 || count==400,"Unsupported crash-wipe grid");bytes=96+272*count;}
 }
 u64 read(u32 p,unsigned n)const{
  u64 value=0;
  if(p==gs_context+8 && n==4)return queue;
  const std::uint8_t* data=nullptr;
  if(contains(p,n,stack_base,stack.size()))data=stack.data()+p-stack_base;
  else if(contains(p,n,packet_base,packet.size()) && packet_live)data=packet.data()+p-packet_base;
  else {
   check((task && contains(p,n,task,48)) || (payload && contains(p,n,payload,bytes)) ||
    contains(p,n,0x237c98,0x58) || contains(p,n,0x237290,4) || contains(p,n,0x211ef0,16),"Undeclared crash-wipe guest read");
   data=mem.bytes(p,n).data();
  }
  for(unsigned i=0;i<n;++i)value|=u64(data[i])<<(8*i);return value;
 }
 void write(u32 p,u64 v,unsigned n){
  std::uint8_t* data=nullptr;
  if(contains(p,n,stack_base,stack.size()))data=stack.data()+p-stack_base;
  else if(contains(p,n,packet_base,packet.size()) && packet_live)data=packet.data()+p-packet_base;
  if(data){for(unsigned i=0;i<n;++i)data[i]=std::uint8_t(v>>(8*i));return;}
  check(writable && ((task && contains(p,n,task,48)) || (payload && contains(p,n,payload,bytes))),"Undeclared crash-wipe guest write");
  std::array<std::uint8_t,8> b{};for(unsigned i=0;i<n;++i)b[i]=std::uint8_t(v>>(8*i));writable->write_bytes(p,std::span(b).first(n));
 }
 Quad read_quad(u32 p)const{check(!(p&15),"Unaligned crash-wipe LQ");return {read(p,8),read(p+8,8)};}
 void write_quad(u32 p,Quad q){check(!(p&15),"Unaligned crash-wipe SQ");write(p,q.lo,8);write(p+8,q.hi,8);}
 Vec vec(u32 p)const{Vec v{};for(unsigned i=0;i<4;++i)v[i]=std::bit_cast<float>(u32(read(p+4*i,4)));return v;}
 void put(u32 p,const Vec& v){for(unsigned i=0;i<4;++i)write(p+4*i,std::bit_cast<u32>(v[i]),4);}
 Matrix matrix(u32 p)const{return {vec(p),vec(p+16),vec(p+32),vec(p+48)};}
 void put(u32 p,const Matrix& m){for(unsigned i=0;i<4;++i)put(p+16*i,m[i]);}
 void finish_packet(){
  check(packet_live && read(packet_base+16,8)==0x30a9c00000008003ull && read(packet_base+24,8)==0x413,"Unexpected original triangle GIFtag");
  Triangle t{};
  for(unsigned i=0;i<3;++i){const auto p=packet_base+32+48*i;
   check(read(p+16,4)==128 && read(p+20,4)==128 && read(p+24,4)==128,"Unexpected triangle modulation");
   const auto a=u32(read(p+28,4));check(a<=128 && (!i || a==t.alpha),"Unexpected triangle alpha");t.alpha=a;
   t.vertices[i]={i32(read(p,4)),i32(read(p+4,4)),i32(read(p+32,4)),i32(read(p+36,4)),i32(read(p+40,4))};
  }
  triangles.push_back(t);packet_live=false;
 }
 bool dispatchGuestBranch(std::uint8_t*,R5900Context*,u32,u32,u32,GuestBranchKind,const char*);
};
#define PS2_POR(a,b) (Quad{(a).lo|(b).lo,(a).hi|(b).hi})
#define READ32(p) u32(runtime->read(p,4))
#define FAST_READ32(p) READ32(p)
#define READ64(p) runtime->read(p,8)
#define READ128(p) runtime->read_quad(p)
#define WRITE32(p,v) runtime->write(p,u32(v),4)
#define WRITE64(p,v) runtime->write(p,u64(v),8)
#define WRITE128(p,v) runtime->write_quad(p,v)
#define GPR_S32(c,n) std::bit_cast<i32>((c)->word(n))
#define GPR_S64(c,n) std::bit_cast<std::int64_t>((c)->r[n].lo)
#define SLL32(v,s) (u32(v)<<((s)&31))
#define SRL32(v,s) (u32(v)>>((s)&31))
#define FPU_CVT_W_S(a) static_cast<i32>(std::clamp(double(ordinary(a)),double(INT32_MIN),double(INT32_MAX)))
#define FPU_NEG_S(a) (-ordinary(a))
#define FPU_MUL_S(a,b) round_towards_zero(double(a)*double(b))
#define FPU_SET_ACC(c,v) ((c)->f_acc=(v))
#define PS2X_STRICT_RETURN_DIAGNOSTICS 1
#include "screen_mesh_generated.hpp"
#include "screen_mesh_rng_generated.hpp"
bool PS2Runtime::dispatchGuestBranch(std::uint8_t* ram,R5900Context* c,u32 target,u32 pc,u32 resume,GuestBranchKind kind,const char*){
 check(!c->in_delay_slot && c->pc==target,"Crash-wipe call ran before its delay slot");
 if(kind==GuestBranchKind::Return)return false;
 if(kind==GuestBranchKind::DirectJump){
  if(entry==0x191418 && target==0x17a5f8 && c->word(4)==payload){freed=true;c->pc=c->word(31);return false;}
  if(entry==0x190ed8 && writable && (target==0x10c368 || target==0x17a198)){
   screen_transition_service(*writable,target,c->word(4));c->pc=c->word(31);return false;}
  fail(pc,target,"Unknown tail call");
 }
 check(kind==GuestBranchKind::DirectCall && c->word(31)==resume && resume==pc+8,"Invalid crash-wipe call ABI");
 auto nested=[&](auto fn){fn(ram,c,this);check(c->pc==resume,"Invalid original nested return");return true;};
 const auto a=c->word(4),b=c->word(5),d=c->word(6);
 switch(target){
 case 0x190d98:return nested(FUN_00190d98_0x190d98);
 case 0x1912d8:return nested(FUN_001912d8_0x1912d8);
 case 0x17a8b0:return nested(FUN_0017a8b0_0x17a8b0);
 case 0x17a6e8:check(writable && entry==0x1904d0,"Unexpected mesh RNG");c->set32(2,source_random_word(*writable,services));break;
 case 0x179b58:check(writable && !task && a==2 && entry==0x1904d0,"Unexpected mesh allocation");bind(reserve_mode_two_task(*writable),false);c->set32(2,task);break;
 case 0x179c40:case 0x179c48:case 0x179c58:case 0x179c60:
  check(a==task && writable,"Unexpected original task setter");
  write(task+(target==0x179c40?20:target==0x179c48?24:target==0x179c58?32:12),b,4);break;
 case 0x17a560:
  check(entry==0x1904d0 && writable && task && !payload && a==bytes && b==0x22f488 && d==0xe7 && !c->word(7) && c->word(8)==13,"Unexpected crash-wipe allocation ABI");
  payload=mesh_begin+(task-mem.read_u32(0x2388bc))/48*mesh_stride;c->set32(2,payload);break;
 case 0x13d098:case 0x17a1a8:case 0x179c80:
  check(writable && entry==0x190ed8,"Unexpected mesh transition service");c->set32(2,screen_transition_service(*writable,target,a));break;
 case 0x1f08f0:c->f[0]=source_visual_tangent(mem,c->f[12]);break;
 case 0x1c1888:put(a,identity());break;
 case 0x1c1590:put(a,product(matrix(b),matrix(d)));break;
 case 0x1c1620:put(a,normalized(vec(b)));break;
 case 0x1c17e0:put(a,translated(matrix(b),vec(d)));break;
 case 0x1c1928:case 0x1c19d0:case 0x1c1a78:
  put(a,product(rotation(c->f[12],target==0x1c1928?2:target==0x1c19d0?0:1,vec(0x211ef0)),matrix(b)));break;
 case 0x1c1d70:{std::array<float,9> args{};std::copy_n(c->f.begin()+12,8,args.begin());args[8]=std::bit_cast<float>(u32(read(c->word(29),4)));put(a,projection(args));break;}
 case 0x17ad38:vu=matrix(a);matrix_loaded=true;break;
 case 0x17ad50:{check(matrix_loaded,"Projection before original matrix load");const auto result=projected_fixed4(vu,vec(b));for(unsigned i=0;i<4;++i)write(a+4*i,u32(result[i]),4);break;}
 case 0x1f90a0:c->set64(2,std::bit_cast<u64>(double(ordinary(c->f[12]))));break;
 case 0x1f9800:{const double x=std::bit_cast<double>(c->r[4].lo),y=std::bit_cast<double>(c->r[5].lo);check(std::isfinite(x)&&std::isfinite(y),"Nonfinite original double comparison");c->set32(2,x<y?u32(-1):x>y?1:0);break;}
 case 0x1f93f8:case 0x1f9460:{const double x=std::bit_cast<double>(c->r[4].lo),y=std::bit_cast<double>(c->r[5].lo);check(std::isfinite(x)&&std::isfinite(y),"Nonfinite original double operation");
  check(target!=0x1f93f8 || x==0,"Unrecovered general software-double subtraction");
  c->set64(2,std::bit_cast<u64>(target==0x1f93f8?x-y:source_double_product(x,y)));break;}
 case 0x1f99d0:{const double x=std::bit_cast<double>(c->r[4].lo);c->f[0]=source_double_to_float(x);break;}
 case 0x179de0:check(a==gs_context && b==0x1680 && stage++==0,"Unexpected saved field upload");break;
 case 0x176c48:check(a==gs_context && stage++==1,"Unexpected crash-wipe GS reset");break;
 case 0x177038:check(a==gs_context && c->r[5].lo==0x628029680ull && !d && stage++==2,"Unexpected crash-wipe texture binding");break;
 case 0x150b00:check(entry==0x191168 && stage==3 && !packet_live,"Unexpected triangle allocation");packet.fill(0);packet_live=true;c->set32(2,packet_base);break;
 case 0x17ab78:check(a==queue && b==packet_base && d==11 && packet_live,"Unexpected original triangle queue");break;
 case 0x17acf8:{const auto v=vec(b);for(unsigned i=0;i<4;++i){const auto f=v[i]*16;check(std::isfinite(f)&&double(f)>=INT32_MIN&&double(f)<=INT32_MAX,"UV fixed4 overflow");write(a+4*i,u32(i32(f)),4);}break;}
 case 0x150b18:check(a==packet_base+176,"Unexpected triangle packet end");finish_packet();break;
 default:fail(pc,target,"Unrecovered original call");
 }
 c->pc=resume;return true;
}
void run(PS2Runtime& r,R5900Context& c){
 c.pc=r.entry;c.set32(29,stack_top);c.set32(31,return_pc);
 switch(r.entry){
 case 0x1904d0:FUN_001904d0_0x1904d0(nullptr,&c,&r);break;
 case 0x190ed8:FUN_00190ed8_0x190ed8(nullptr,&c,&r);break;
 case 0x191168:FUN_00191168_0x191168(nullptr,&c,&r);break;
 case 0x191418:FUN_00191418_0x191418(nullptr,&c,&r);break;
 default:fail(r.entry,0,"Unknown crash-wipe entry");
 }
 check(c.pc==return_pc && c.word(29)==stack_top && !c.in_delay_slot,"Original crash-wipe returned incorrectly");
}
}
u32 create(GuestMemory& m,std::span<const u32> args,ExecutionServices* services){
 check(args.size()==6 && (args[1]==12 || args[1]==25) && args[2]==8 && args[0]<=180 && args[3]==320 && args[4]==114 && args[5]==10,"Unsupported original crash-wipe arguments");
 PS2Runtime r{m,&m,0x1904d0};r.services=services;r.bytes=96+args[1]*args[2]*544;
 R5900Context c;for(unsigned i=0;i<6;++i)c.set32(4+i,args[i]);run(r,c);
 check(c.word(2)==r.task && m.read_u32(r.task+44)==r.payload,"Invalid constructed crash-wipe task");return r.task;
}
void update(GuestMemory& m,u32 task,ExecutionServices* services){PS2Runtime r{m,&m,0x190ed8};r.services=services;r.bind(task,true);R5900Context c;c.set32(4,task);run(r,c);}
void release(GuestMemory& m,u32 task){PS2Runtime r{m,&m,0x191418};r.bind(task,true);R5900Context c;c.set32(4,task);run(r,c);check(r.freed,"Original mesh work was not released");}
std::vector<Triangle> draw(const GuestMemory& m,u32 task){PS2Runtime r{m,nullptr,0x191168};r.bind(task,true);R5900Context c;c.set32(4,task);c.set32(5,gs_context);run(r,c);check(r.stage==3&&!r.packet_live,"Incomplete original crash-wipe draw");return r.triangles;}
}
