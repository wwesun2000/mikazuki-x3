#include "timechart_native.hpp"
#include "choice_pipeline.hpp"
#include "control_transfer.hpp"
#include "guest_memory.hpp"
#include "source_libc.hpp"
#include "native_scalar.hpp"
#include <array>
#include <bit>
#include <cstdint>
#include <stdexcept>

namespace kx3 {
namespace {
using u32=std::uint32_t;
using u64=std::uint64_t;
using i64=std::int64_t;
constexpr u32 device=0x1e41c60;
std::int32_t s32(u64 value){return std::bit_cast<std::int32_t>(u32(value));}
i64 s64(u64 value){return std::bit_cast<i64>(value);}
u64 sx32(u64 value){return u64(i64(s32(value)));}
}

void sample_chart_directions(GuestMemory& m,std::uint16_t held){ // 15EE40 primary device lane.
    const auto dpad=std::uint16_t(held&0xf0);
    m.write_u16(device+0x100,dpad);m.write_u32(device+0xf0,1);
    // The native adapter supplies one source tick and a live primary controller.
    if(!dpad){m.write_u32(device+0xf4,0);m.write_u32(device+0xf8,0);}
    else if(!m.read_u32(device+0xf4))m.write_u32(device+0xf8,m.read_u32(device+0xf8)-1);
    m.write_u16(device+0x102,m.read_u16(device+0x102)&held);
}
std::uint16_t chart_direction_repeat(GuestMemory& m){ // 15FF88 -> 15F558.
    if(m.read_u32(0x1e497e0))return 0;
    if(m.read_u32(device+0xf0)){
        const auto current=m.read_u16(device+0x100),prev=m.read_u16(device+0x102);
        m.write_u32(device+0xf0,0);m.write_u16(device+0x104,current);
        if(!prev)m.write_u32(device+0xf8,30);
        else if((current&~prev) || s32(m.read_u32(device+0xf8))<1)m.write_u32(device+0xf8,6);
        else m.write_u16(device+0x104,0);
        m.write_u16(device+0x102,current);
    }
    return m.read_u16(device+0x104);
}
namespace {
// Private C++ storage for the original chart calls' ABI spill slots and local
// arrays. Chart buffers, game variables, file strings and progress all access
// the shared guest RAM. No guest stack is persisted by the native ABI.
struct ChartRegisters : scalar::ScalarRegisters {
    using scalar::ScalarRegisters::ScalarRegisters;
    void leaf(u32 entry){
        switch(entry){
        case 0x100ec8: // LH in the JR delay slot returns a sign-extended story variable.
            v0=run_scenario_return(m,entry,u32(a0),0,services);return;
        case 0x100ee0:m.write_u16(0x238af0+2*u32(a0),std::uint16_t(a1));return;
        case 0x14bd18:v0=invoke_recovered(m,entry,u32(a0),0,0,0,services);return;
        case 0x10c898:{
            const auto script=m.read_u32(m.read_u32(0x235e40)+0x38);
            v0=invoke_recovered(m,0x10ee18,script,a0,0,0,services);return;
        }
        case 0x15f528:m.write_u32(device+0xf8,1);m.write_u32(device+0xf4,1);return;
        case 0x15fde0:case 0x15fe30:case 0x15ff88:{
            const bool available=!m.read_u32(0x1e497e0);
            std::uint16_t buttons=0;
            if(available){
                if(entry==0x15ff88)buttons=chart_direction_repeat(m);
                else if(entry==0x15fe30){
                    buttons=choice_device_edges(m,device);
                    if(services && services->choice_input && services->choice_input->menu_confirm &&
                       services->choice_input->menu_index>=0 && m.read_u32(0x2381dc)){
                        const auto index=u32(services->choice_input->menu_index);
                        const auto work=m.read_u32(0x2381dc),row=index/4,actor=index%4;
                        if(row==m.read_u32(work+12) && actor==m.read_u32(work+8) &&
                           row<m.read_u32(0x2389a0) && actor<m.read_u32(0x2389a4) &&
                           m.read_u32(m.read_u32(0x2381c4)+row*88+actor*20+24))buttons|=0x2000;
                    }
                }
                else buttons=m.read_u16(device+8);
            }
            write(u32(a0),buttons,2);v0=available && m.read_u32(device);return;
        }
        case 0x175f78:v0=0;return;
        case 0x19cf38:v0=0x1e4abb0;return;
        case 0x1b15f0:v0=invoke_recovered(m,entry,u32(a0),a1,a2,a3,services);return;
        case 0x1fc490:{
            for(u32 i=0;i<u32(a2);++i){
                const int delta=int(lbu(u32(a0)+i))-int(lbu(u32(a1)+i));
                if(delta){v0=sx32(delta);return;}
            }
            v0=0;return;
        }
        case 0x1fda0c:{
            for(u32 i=0;;++i){
                const auto left=lbu(u32(a0)+i),right=lbu(u32(a1)+i);
                if(left!=right || !left){v0=sx32(left-right);return;}
            }
        }
        default:throw std::logic_error("Invalid static chart target");
        }
    }
};
#include "timechart_blocks.hpp"
}
bool has_timechart_native(u32 entry){
    return entry==0x1ac690 || entry==0x1ad3d8 || entry==0x1adbd8 || entry==0x1adcd0 || entry==0x1add08 || entry==0x1add40 ||
           entry==0x1ae388 || entry==0x1ad2c0 || entry==0x1ac860;
}
u64 invoke_timechart_native(GuestMemory& m,u32 entry,u32 a0,u64 a1,ExecutionServices* s){
    ChartRegisters regs{m,s};regs.a0=a0;regs.a1=a1;
    switch(entry){
    case 0x1ac690:chart_1ac690(regs);break;
    case 0x1ad3d8:chart_1ad3d8(regs);break;
    case 0x1adbd8:chart_1adbd8(regs);break;
    case 0x1adcd0:chart_1adcd0(regs);break;
    case 0x1add08:chart_1add08(regs);break;
    case 0x1add40:chart_1add40(regs);break;
    case 0x1ae388:chart_1ae388(regs);break;
    case 0x1ad2c0:chart_1ad2c0(regs);break;
    case 0x1ac860:chart_1ac860(regs);break;
    default:throw std::invalid_argument("Unknown native chart entry");
    }
    return regs.v0;
}
bool chart_save_indices(GuestMemory& m,u32& first,u32& second){
    ChartRegisters regs{m,nullptr};
    constexpr u32 outputs=ChartRegisters::stack_start+0xf00;
    regs.a0=outputs;regs.a1=outputs+4;
    chart_1ad3d8(regs);
    first=u32(regs.lw(outputs));second=u32(regs.lw(outputs+4));
    return regs.v0!=0;
}
}
