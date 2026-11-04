#include "scenario_checkpoint.hpp"
#include "choice_pipeline.hpp"
#include "control_transfer.hpp"
#include "recovered.hpp"
#include "source_libc.hpp"
#include "timechart_native.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <sstream>

namespace kx3 {
namespace {
using u32=std::uint32_t;
constexpr u32 header=0x239e00,descriptors=header+0x30,request=0x239fa0,bank_table=0x235b28;
constexpr u32 bank_capacity=0x40000,first_bank=0x1380000,card_ui=0x1400000;
constexpr u32 gp=0x23daf0;
void copy(GuestMemory& m,u32 dest,u32 src,u32 length){(void)source_memcpy(m,dest,src,length);}
void clear(GuestMemory& m,u32 dest,u32 length){m.write_bytes(dest,std::vector<std::uint8_t>(length));}
void make_header(GuestMemory& m,u32 base,u32 size){ // 1025E0
    (void)source_strcpy(m,base,0x2281c0);
    clear(m,base+16,16);m.write_u32(base+32,size);clear(m,base+36,12);
}
void init_directory(GuestMemory& m,u32 base){ // 1061F0 (also used for the 10 slot headers).
    make_header(m,base,0x5e0);m.write_u32(base+0xb4,0);m.write_u32(base+0xb0,1);
    clear(m,0x239ef0,32);clear(m,base+0xb8,56);m.write_u8(base+0x110,0);
    u32 offset=0x140;
    for(u32 i=0;i<8;++i){
        const auto row=base+0x30+16*i,n=m.read_u32(0x2280fc+12*i);
        m.write_u32(row,n);m.write_u32(row+4,offset);m.write_u32(row+8,0);m.write_u32(row+12,0);
        offset+=n+m.read_u32(0x228100+12*i);
    }
}
void reset_request(GuestMemory& m,u32 p){ // 102788
    for(unsigned i=0;i<9;++i)m.write_u32(p+4*i,(i==2 || i==3 || i==4 || i==5 || i==8)?UINT32_MAX:0);
}
void write_registry(GuestMemory& m,u32 dest){ // 10BDFamily: 10BD50 -> 10BBF8.
    const auto reg=m.read_u32(0x235cd8),count=m.read_u32(reg+0xf4);
    if(count>20)throw std::runtime_error("Invalid original checkpoint object registry");
    for(u32 i=0;i<count;++i){
        const auto row=reg+4+12*i,self=m.read_u32(row),out=dest+m.read_u32(row+8);
        const auto entry=m.read_u32(m.read_u32(self));
        switch(entry){
        case 0x113c40:
            for(u32 n:{0u,3u,1u,2u,4u,5u,6u,7u})m.write_u32(out+4*n,m.read_u32(self+4+4*n));
            break;
        case 0x114ed8:m.write_u32(out,m.read_u32(self+12));break;
        case 0x1160d8:
            for(u32 n=1;n<=3;++n)m.write_u32(out+4*n,m.read_u32(self+4+4*n));
            break;
        case 0x11a098:m.write_u32(out,m.read_u32(self+48));break;
        case 0x204a70:m.write_u32(out,m.read_u32(self-20+28));break;
        case 0x10f4e0:{
            m.write_u32(out,m.read_u32(self+208));m.write_u32(out+4,m.read_u32(self+212));
            m.write_u32(out+8,m.read_u32(self+224));copy(m,out+12,self+228,80);
            const auto n=m.read_u32(self+308);
            if(m.read_u32(row+4)<96 || n>(m.read_u32(row+4)-96)/8)
                throw std::runtime_error("Script history exceeds its original save allocation");
            m.write_u32(out+92,n);copy(m,out+96,m.read_u32(self+312),n*8);break;
        }
        default:{
            std::ostringstream s;s<<"Unrecovered original save writer 0x"<<std::hex<<entry;throw std::runtime_error(s.str());
        }}
    }
}
void stage_card_refresh(GuestMemory& m){ // 1031C8(5), single-owner native card worker
    if(m.read_u32(gp-32660)==5)return;
    for(u32 i=0;i<2;++i){
        const auto p=0x23a000+36*i;
        m.write_u32(p,0);m.write_u32(p+4,i);m.write_u32(p+12,0);m.write_u32(p+32,0);
        for(u32 offset:{8u,16u,20u,24u,28u})m.write_u32(p+offset,UINT32_MAX);
    }
    const auto ui=m.read_u32(gp-32644);
    if(!ui)throw std::runtime_error("Uninitialized native memory-card directory");
    m.write_u32(gp-32652,1);m.write_u32(ui,0);
    for(u32 i=0;i<10;++i){
        m.write_u32(ui+36+4*i,0);
        const auto row=ui+76+32*i;clear(m,row,16);
        m.write_u32(row+16,1);m.write_u32(row+20,1);m.write_u32(row+24,2000);
        init_directory(m,ui+396+316*i);
    }
    m.write_u32(gp-32648,1);m.write_u32(gp-32656,1);m.write_u32(gp-32660,5);
    m.write_u32(0x1353000,1); // 10327C wakes the original directory scanner.
}
void write_header(GuestMemory& m,u32 out,u32 script){
    // 106338: 15DFF8 copies the original sound/display preference record.
    copy(m,0x239f20,0x207c08,16);clear(m,0x239f30,12);
    for(u32 i=0;i<2;++i){
        const auto name=script+0xe4+16*i;
        clear(m,0x239ef0+16*i,16);
        for(u32 n=0;n<14;++n){const auto ch=m.read_u8(name+n);if(!ch)break;m.write_u8(0x239ef0+16*i+n,ch);}
    }
    // 106338 stores the 32-bit result of the original signed variable getter.
    auto variable=[&](u32 n){return u32(run_scenario_return(m,0x100ec8,n,0,nullptr));};
    u32 flags=0;
    if(m.read_u32(0x235b00)==1)flags=(variable(381)==1?1u:0u)|(variable(380)==1?2u:0u)|(variable(382)==1?4u:0u);
    const auto n=m.read_u32(0x2381a0);
    if(n>128)throw std::runtime_error("Invalid original ending count in checkpoint");
    std::array<unsigned,3> totals{};
    if(m.read_u32(0x2381a4))for(u32 i=0;i<n;++i){
        const auto type=m.read_u8(m.read_u32(0x1e4bd08+i*4));
        if(type<3 && (m.read_u8(0x1e4bf08+i/8)&(1u<<(i%8))))++totals[type];
    }
    m.write_u32(header+0xb8,totals[1]);m.write_u32(header+0xbc,totals[2]);m.write_u32(header+0xc0,flags);
    const auto label=m.read_u32(script+0xd0)<32 ? u32(invoke_recovered(m,0x10d750,script)) : 0x235e48u;
    const auto group=source_label_category(m,label),chapter=source_label_chapter(m,label);
    m.write_u32(header+0xc4,group==255?m.read_u8(0x237f8a):group);
    m.write_u32(header+0xc8,chapter==255?m.read_u8(0x237f8b):chapter);
    u32 first=0,second=0;
    (void)chart_save_indices(m,first,second);
    m.write_u32(header+0xcc,first);m.write_u32(header+0xd0,second);
    m.write_u32(header+0xd4,m.read_u32(0x2381b8)?m.read_u32(0x238954):0);
    for(u32 i=0;i<4;++i)m.write_u32(header+0xd8+4*i,variable(400+i));
    copy_name13(m,0x239f10,0x1e4abb0);
    m.write_u32(header+0xb4,m.read_u32(0x239fe8));m.write_u32(header+40,m.read_u32(header+40)+1);
    copy(m,out,header,0x13c);
}
}
void install_scenario_checkpoint(GuestMemory& m){
    GuestMemory::Transaction tx(m);
    // 1020D8: shared directory lock, transfer lock, and the scanner's second list.
    for(u32 lock:{0x204bc0u,0x204be0u})if(!m.read_u32(lock) || m.read_u32(lock)==UINT32_MAX){
        m.write_u32(lock,lock==0x204bc0?8:9);m.write_u32(lock+4,UINT32_MAX);
        m.write_u32(lock+8,0);m.write_u32(lock+12,lock==0x204bc0?19:0);
    }
    if(!m.read_u32(0x235b70))m.write_u32(0x235b70,0x1354000);
    // 100874..100894 selects 1, 2 or 3 for the JAL at 1009A0 using 100410's
    // current program. Both the scan mode and the DATA prefix receive it.
    if(!m.read_u32(0x235b20)){
        const auto program=m.read_u32(0x235b00);
        if(program>2)throw std::runtime_error("Unknown original card program");
        m.write_u32(0x235b20,program+1);m.write_u32(0x235b24,program+1);
        if(m.read_u32(bank_table) && m.read_u32(0x235b58)){
            // Old native snapshots may contain a directory scanned before
            // the scenario prefix was initialized. Ask 103640 to rescan.
            m.write_u32(0x235b64,1);m.write_u32(0x235b68,1);
            m.write_u32(0x1353000,1);m.write_u32(0x1353008,0);
        }
    }
    if(m.read_u32(bank_table)){tx.commit();return;}
    // 102E00, 10BBA0, 102F30. Registry capacities are per-program.
    // Preserve chart slot 5, whose file loader has published its bitset size.
    const auto chart_size=m.read_u32(descriptors+5*16+8);
    init_directory(m,header);m.write_u32(descriptors+5*16+8,chart_size);
    reset_request(m,0x239fd0);reset_request(m,0x239f40);reset_request(m,request);
    m.write_u32(request+16,0);m.write_u32(request+20,0);copy(m,0x239f70,request,48);
    const auto reg=m.read_u32(0x235cd8),count=m.read_u32(reg+0xf4);
    if(count>20)throw std::runtime_error("Invalid 10BBA0 registry count");
    u32 bytes=0;m.write_u32(reg+0xf8,1);
    for(u32 i=0;i<count;++i){
        m.write_u32(reg+12+12*i,bytes);
        const auto row=m.read_u32(reg+8+12*i);
        if(row>bank_capacity-bytes)throw std::runtime_error("Oversized 10BBA0 registry");
        bytes+=row;
    }
    m.write_u32(descriptors+16+8,bytes);m.write_u32(descriptors+7*16+8,16);
    u32 total=0x5e0;
    for(u32 i=0;i<8;++i){
        const auto row=descriptors+16*i,n=m.read_u32(row+8);if(!n)continue;
        if(n>bank_capacity-total)throw std::runtime_error("Oversized original save area");
        m.write_u32(row+12,total);total=(total+n+15)&~15u;
    }
    total=(std::max(total,0xf000u)+2047)&~2047u;
    if(total>bank_capacity)throw std::runtime_error("Original card exceeds reserved workspace");
    make_header(m,header,total);
    for(u32 i=0;i<2;++i){const auto p=first_bank+i*bank_capacity;m.write_u32(bank_table+i*4,p);clear(m,p,total);}
    m.write_u32(gp-32644,card_ui);
    // 15DE08 defaults, subsequently updated by the system settings menu.
    for(unsigned i=0;i<7;++i)m.write_u32(0x207c08+i*4,(i==0 || i==1 || i==3)?1:0);
    tx.commit();
}
void advance_record_timer(GuestMemory& m){ // 102548, once per 1032B8 update
    for(u32 i=0;i<4;++i){
        const auto p=header+16+4*i,next=m.read_u32(p)+1;
        if(i==3 || std::bit_cast<std::int32_t>(next)<60){m.write_u32(p,next);return;}
        m.write_u32(p,0);
    }
}
bool has_checkpoint_writer(u32 entry){
    switch(entry){
    case 0x10bd50:case 0x101080:case 0x19ce48:case 0x1abfa0:
    case 0x1adab0:case 0x1af4b0:case 0x106690:case 0x106338:return true;
    default:return false;
    }
}
std::uint64_t checkpoint_writer(GuestMemory& m,u32 entry,u32 out,u32 extra){
    switch(entry){
    case 0x10bd50:write_registry(m,extra);break;
    case 0x101080:copy(m,out,0x238af0,1024);break;
    case 0x19ce48:
        copy(m,out,0x237f88,2);copy_name13(m,out+2,0x1e4abb0);copy_name13(m,out+15,0x1e4aba0);
        m.write_u32(out+28,m.read_u32(0x237f8c));m.write_u8(out+32,m.read_u8(0x237f8a));
        m.write_u8(out+33,m.read_u8(0x237f8b));break;
    case 0x1abfa0:
        if(m.read_u32(0x2381a4)){
            m.write_u32(out,m.read_u32(0x2381a0));copy(m,out+4,0x1e4bf08,16);
        }else clear(m,out,20);
        break;
    case 0x1adab0:
        if(m.read_u32(0x2381b8)){
            m.write_u32(out+8,m.read_u32(0x238998));m.write_u32(out+4,m.read_u32(0x238954));
            copy(m,extra,m.read_u32(0x2381c0),m.read_u32(0x23899c));
        }else m.write_u32(out+8,0);
        break;
    case 0x1af4b0:
        if(m.read_u32(0x238208)){
            m.write_u32(out,m.read_u32(0x238204));copy(m,out+4,0x1e4c180,16);
        }else m.write_u32(out,0);
        break;
    case 0x106690:copy(m,out,0x2281c0,11);copy(m,extra,0x2281c0,11);break;
    case 0x106338:write_header(m,out,m.read_u32(m.read_u32(0x235e40)+0x38));break;
    default:throw std::invalid_argument("Unknown 104E10 section writer");
    }
    return 1;
}
std::uint64_t write_scenario_checkpoint(GuestMemory& m,ExecutionServices* services){ // 104E10
    if(m.read_u32(0x235b3c) || m.read_u32(request+4)>=2)return 0;
    const auto slot=m.read_u32(request+16);
    if(slot>1)throw std::runtime_error("Invalid active original memory-card bank");
    const auto out=m.read_u32(bank_table+4*slot);
    if(!out)throw std::runtime_error("104E10 requires the original checkpoint buffers");
    constexpr u32 writers[]{0x106338,0x10bd50,0x101080,0x19ce48,0x1abfa0,0x1adab0,0x1af4b0,0x106690};
    constexpr u32 positions[]{0,0x140,0x150,0x550,0x580,0x5a0,0x5b0,0x5d0};
    for(u32 i:{1u,2u,3u,4u,5u,6u,7u,0u}){
        const auto row=descriptors+16*i;
        const auto extra=std::bit_cast<std::int32_t>(m.read_u32(row+8))>0?out+m.read_u32(row+12):0;
        if(i==7)m.write_u32(header+0xb0,0);
        if(!checkpoint_writer(m,writers[i],out+positions[i],extra))return 0;
    }
    m.write_u32(request+4,1);stage_card_refresh(m);
    if(services && services->system_record_requested)*services->system_record_requested=true;
    return 1;
}
}
