#include "title_selection.hpp"
#include "control_transfer.hpp"
#include "recovered.hpp"
#include <algorithm>
#include <stdexcept>

namespace kx3 {
TitleAction advance_title_selection(GuestMemory& memory,TitleSelection& title,std::uint16_t pressed,ExecutionServices& services){
    if(title.focus>=title.rows.size())throw std::runtime_error("Title focus outside the retail table");
    // 108C1C..108C40 / 109EC4..109EE8 install each work list's real
    // table, focus and initial action. A title interaction never commits its
    // window work area or its EE stack into the session used for continuing.
    GuestMemory::Transaction title_window(memory);
    const auto owner=title.load?0x23a258u:0x23a138u;
    memory.write_u32(owner+4,title.load?0x2289c8:0x228648);
    memory.write_u32(owner+8,title.focus);
    memory.write_u32(owner+12,UINT32_MAX);
    memory.write_u32(owner+16,3);
    auto io=services;io.title_buttons=&pressed;
    const auto pending=run_vm_context(memory,title.load?0x10a000:0x108d58,0,owner,0,0,&io);
    const auto focus=memory.read_u32(owner+8);
    if(focus>=title.rows.size())throw std::runtime_error("Retail title picker returned invalid focus");
    const auto destination=memory.read_u32(owner+16);
    if(!pending && destination!=3 && destination!=title.rows[focus].mode)
        throw std::runtime_error("Work selector result differs from the retail file table");
    title.focus=focus;
    return pending?TitleAction::idle:destination==3?TitleAction::back:TitleAction::accept;
}
TitleSelection source_title_selection(const GuestMemory& m,bool load){
    const auto names=load?0x2289b0u:0x228630u,actions=load?0x2289c8u:0x228648u;
    TitleSelection result;
    result.load=load;
    result.focus=2; // Both original scans start at row two if no stored work matches.
    const auto previous_mode=m.read_u32(0x235b00); // 1002C8 / 10033C pass GP-0x7ff0.
    if(m.read_u32(actions)!=result.rows.size())throw std::runtime_error("Invalid original work selection count");
    const auto read_name=[&](unsigned address){
        const auto bytes=m.bytes(address,64);const auto end=std::find(bytes.begin(),bytes.end(),0);
        if(end==bytes.end())throw std::runtime_error("Invalid original work name");
        return std::string(bytes.begin(),end);
    };
    for(unsigned i=0;i<result.rows.size();++i){
        const auto action=m.read_u32(actions+4+4*i);
        if(action>=3)throw std::runtime_error("Unknown 108D58 title action");
        // 108D58 and 10A000 map the three actions to game 2, 0 and 1.
        constexpr unsigned modes[]{2,0,1};const auto mode=modes[action];
        if(m.read_u32(names+8*i+4)!=mode)throw std::runtime_error("Original work/order mismatch");
        const auto cmd=read_name(m.read_u32(names+8*i));
        const auto files=m.read_u32(0x204b88+4*mode);
        const auto font=read_name(m.read_u32(files+4)),scene=read_name(m.read_u32(files+20));
        const std::string prefix="edit0:SCENARIO/";const std::string suffix=".fnt";
        if(m.read_u32(files)!=4 || m.read_u32(files+16)!=2 || !font.starts_with(prefix) || !font.ends_with(suffix))
            throw std::runtime_error("Invalid 100548 source file table");
        const auto program=font.substr(prefix.size(),font.size()-prefix.size()-suffix.size());
        if(program.size()<3 || scene!=prefix+program+".spk" || cmd!="Game S"+program.substr(1))
            throw std::runtime_error("Selected title does not match original font and scenes");
        result.rows[i]={mode,program};
        if(mode==previous_mode)result.focus=i;
    }
    return result;
}
}
