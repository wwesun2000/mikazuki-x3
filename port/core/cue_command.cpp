#include "cue_command.hpp"
#include "audio_worker.hpp"
#include "guest_memory.hpp"
#include "source_libc.hpp"
#include "control_transfer.hpp"
#include <bit>
#include <sstream>

namespace kx3 {
namespace {
using u32=std::uint32_t;
using u64=std::uint64_t;
constexpr u32 loader=0x206250, write_index=0x23871c, read_index=0x238720, active=0x238724;
constexpr u32 cue_lock=0x207140, programs=0x23c1d0, names=0x23c1f0;
constexpr u32 delays_tail=0x206dcc, delays_head=0x206dd0;

[[noreturn]] void unknown(u32 address,const char* why) {
    std::ostringstream os; os<<"Unrecovered source 0x"<<std::hex<<address<<" ("<<why<<")";
    throw std::runtime_error(os.str());
}
int count16(GuestMemory& m,u32 p){return std::bit_cast<std::int16_t>(m.read_u16(p));}
u32 current_manager(GuestMemory& m){return u32(invoke_recovered(m,0x10fb38,0));}
u32 ring_index(GuestMemory& m,u32 field,u32 capacity){
    const auto i=m.read_u32(field);
    if(i>=capacity)throw std::runtime_error("Invalid source queue index");
    return i;
}

struct SceneRow { u32 name=0, group=0; };
// 101DC0 copies the cue prefix up to '_' to its stack before hashing. Compare
// the same byte sequence directly; the returned pointer is the resident SPK name.
SceneRow scene_for_cue(GuestMemory& m,u32 registry,u32 token){
    u32 length=0, sum=0;
    for(;;++length){
        const auto b=m.read_u8(token+length); if(!b || b=='_')break;
        sum+=u32(b)<<(b&7);
    }
    const u32 bucket=((sum&255)+(sum>>8))&255;
    const auto blocks=std::bit_cast<std::int32_t>(m.read_u32(registry+0x84));
    for(int i=0;i<blocks;++i){
        const u32 block=m.read_u32(registry+4+4*u32(i));
        u32 table=m.read_u32(block+32+4*bucket);
        if(!table)continue;
        const int n=count16(m,table); table+=2;
        for(int j=0;j<n;++j){
            const auto size=m.read_u16(table); const u32 name=table+10;
            u32 k=0;while(k<length && m.read_u8(name+k)==m.read_u8(token+k))++k;
            if(k==length && !m.read_u8(name+k))return {name,m.read_u32(table+2)};
            table+=2+size;
        }
    }
    return {};
}
// Both 101CA8 and 101928 walk hash, length, NUL name, program pointer and ID.
u32 cue_row(GuestMemory& m,u32 group,u32 token){
    const u32 hash=u32(invoke_recovered(m,0x101b10,token));
    const int count=count16(m,group);
    u32 p=group+2;
    for(int i=0;i<count;++i){
        const u32 name=p+4;
        if(m.read_u16(p)==hash && !source_strcmp(m,name,token))
            return name+source_strlen(m,name)+1;
        p=name+m.read_u16(p+2);
    }
    return 0;
}
u32 cue_id(GuestMemory& m,u32 registry,u32 token){
    const auto scene=scene_for_cue(m,registry,token);
    if(!scene.name)return 0xffffffffu;
    const auto row=cue_row(m,scene.group,token);
    return row ? u32(count16(m,row+4)) : 0xffffffffu;
}

u32 effect_count(GuestMemory& m){ // 10C760 -> 114598
    const auto state=current_manager(m)+0x330;
    if(!m.read_u32(state+0x3ec) || !m.read_u32(state+0x3e8))return 0;
    u32 count=0;for(u32 i=0;i<10;++i)count+=m.read_u32(state+100*i)!=0;
    return count;
}
bool last_sound_busy(GuestMemory& m,ExecutionServices* services){ // 1B1F80 -> 1B1F08.
    const auto id=m.read_u32(0x2389d8);
    if(id==0xffffffffu)return false;
    if(!services || !services->sound_device)unknown(0x1d28b4,"source voice status required");
    if(services->sound_device->effect_active(id))return true;
    const auto misses=m.read_u32(0x2389dc);
    m.write_u32(0x2389dc,misses+1);
    return std::bit_cast<std::int32_t>(misses)<4;
}
// 138C90, 138EB8 and 138D70 share a semaphore. Manager-frame serialization
// already owns this session. Present the released source lock state at return.
void release_queue_lock(GuestMemory& m){
    if(!m.read_u32(cue_lock) || m.read_u32(cue_lock+4)!=0xffffffffu || m.read_u32(cue_lock+12))
        unknown(0x1536a8,"busy or uninitialized cue semaphore");
    m.write_u32(cue_lock+4,0xffffffffu);m.write_u32(cue_lock+8,0);
}
bool pending_delay(GuestMemory& m){
    const u32 tail=ring_index(m,delays_tail,8);
    for(u32 i=ring_index(m,delays_head,8);i!=tail;i=(i+1)%8)
        if(m.read_u32(0x206ddc+52*i))return true;
    return false;
}
void pump(GuestMemory& m,ExecutionServices* services){
    if(!m.read_u32(active) && !pending_delay(m)){
        release_queue_lock(m);
        const auto head=ring_index(m,read_index,8);
        if(head!=ring_index(m,write_index,8)){
            const auto cue=m.read_u32(programs+4*head), name=m.read_u32(names+4*head);
            m.write_u32(read_index,(head+1)%8);
            m.write_u32(active,cue);(void)source_strcpy(m,loader+2868,name);
            m.write_u32(loader+116,0);m.write_u32(loader+120,0);
            m.write_u32(loader+3760,effect_count(m));m.write_u32(loader+608,0);m.write_u32(loader+3584,0);
        }
    }
    if(m.read_u32(active)){run_vm_context(m,0x1397d8,0,0,0,0,services);m.write_u32(loader+124,1);}
    run_vm_context(m,0x139338,0,0,0,0,services);
    m.write_u32(loader+2932,1);
}
void enqueue_cue(GuestMemory& m,u32 program,u32 name){
    const auto tail=ring_index(m,write_index,8), next=(tail+1)%8;
    release_queue_lock(m);
    m.write_u32(write_index,next); // Original advances write index even at overflow.
    if(next!=ring_index(m,read_index,8)){m.write_u32(programs+4*tail,program);m.write_u32(names+4*tail,name);}
}
}

void initialize_cue_queue(GuestMemory& m,u32 handle){
    if(!handle || handle>=0x80000000u)throw std::invalid_argument("Invalid native cue semaphore");
    m.write_u32(cue_lock,handle);m.write_u32(cue_lock+4,0xffffffffu);
    m.write_u32(cue_lock+8,0);m.write_u32(cue_lock+12,0);
    m.write_u8(loader+2868,0);m.write_u32(write_index,0);m.write_u32(read_index,0);m.write_u32(active,0);
}
bool has_cue_command(u32 entry) noexcept{
    switch(entry){
    case 0x127ae8: case 0x1278e8: case 0x11dda8: case 0x10f110: case 0x11e498: case 0x101928:
    case 0x101dc0: case 0x101ca8: case 0x138e10: case 0x1395a8: case 0x1397d8: case 0x138c90:
    case 0x13eff0: case 0x139550: case 0x140aa8: case 0x1407d0:
    case 0x140118: case 0x1390a8: case 0x1b1f80: return true;
    default:return false;
    }
}
u64 invoke_cue_command(GuestMemory& m,u32 entry,u32 self,u64 a1,u64 a2,ExecutionServices* services){
    auto call=[&](u32 address,u32 object,u64 x=0,u64 y=0){return invoke_recovered(m,address,object,x,y,0,services);};
    switch(entry){
    case 0x127ae8:
        (void)call(0x114a78,current_manager(m)+0x330);
        return call(0x1278e8,self,a2);
    case 0x1278e8:{
        const auto script=m.read_u32(current_manager(m)+0x38);
        const auto provider=u32(call(0x11dac0,0));
        (void)call(0x10d638,script);
        const auto token=u32(call(0x10d680,script));
        if(call(0x11dda8,provider,token)){(void)call(0x10f110,script,token);return 0;}
        (void)call(0x10d700,script,a1);return 1;
    }
    case 0x11dda8:{
        const u32 registry=m.read_u32(self+4);
        const auto p=u32(call(0x101ca8,registry,m.read_u32(self+16),a1));
        if(p){(void)call(0x138e10,p,a1);return 1;}
        (void)call(0x11dcf8,self,scene_for_cue(m,registry,u32(a1)).name);
        return 0;
    }
    case 0x10f110:
        m.write_u32(self+0xe0,a1?u32(call(0x11e498,u32(call(0x11dac0,0)),a1)):0xffffffffu);return 0;
    case 0x11e498:return call(0x101928,m.read_u32(self+4),a1);
    case 0x101928:return u64(std::int64_t(std::bit_cast<std::int32_t>(cue_id(m,self,u32(a1)))));
    case 0x101dc0:return scene_for_cue(m,self,u32(a1)).name;
    case 0x101ca8:{const auto p=cue_row(m,u32(a1),u32(a2));return p?m.read_u32(p):0;}
    case 0x138e10:enqueue_cue(m,self,u32(a1));pump(m,services);return 0;
    case 0x138c90:enqueue_cue(m,self,u32(a1));return 0;
    case 0x1395a8:pump(m,services);return 0;
    case 0x1397d8:case 0x139550:case 0x13eff0:case 0x140aa8:case 0x1407d0:
    case 0x140118:case 0x1390a8:return run_vm_context(m,entry,self,a1,a2,0,services);
    case 0x1b1f80:return last_sound_busy(m,services);
    default:throw std::invalid_argument("Unrecognized source cue function");
    }
}
}
