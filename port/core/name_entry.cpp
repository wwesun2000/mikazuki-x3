#include "name_entry.hpp"
#include "native_scalar.hpp"
#include "choice_pipeline.hpp"
#include "control_transfer.hpp"
#include "script_data.hpp"
#include "text_commands.hpp"
#include <algorithm>

namespace kx3 {
namespace {
using namespace scalar;
constexpr u32 arena=0x1360000,arena_limit=0x1380000;
constexpr u32 owner_pointer=0x235e40,name_editor_cell=0x235ed0;
// Only the two native heap boundary words in this reserved region are
// adapter-owned. Everything allocated after them is original guest data.
u32 allocate_name_data(GuestMemory& m,u32 bytes){
    const auto p=(m.read_u32(arena)+15)&~15u;
    if(p<arena+16 || p>arena_limit || bytes>arena_limit-p)throw std::runtime_error("Original name input arena exhausted");
    m.write_u32(arena,p+bytes);return p;
}
struct NameRegisters : ScalarRegisters {
    using ScalarRegisters::ScalarRegisters;
    void leaf(u32 entry){
        switch(entry){
        case 0x1007d8:{
            if(a0!=1)throw std::runtime_error("11BE28 requested an unknown name input resource slot");
            const auto p=m.read_u32(0x238ab0),size=m.read_u32(0x238ab4);
            if(!p)throw std::runtime_error("Original 11BE28 needs ready slot 1 namkan.txt");
            sw(u32(a1),p);sw(u32(a1)+4,size);
            m.write_u32(0x238ab0,0);m.write_u32(0x238ab4,0xffffffffu);v0=1;return;
        }
        case 0x10fad0:case 0x17a560:v0=allocate_name_data(m,u32(a0));return;
        case 0x15fde0:
            sh(u32(a0),m.read_u32(0x1e497e0)?0:m.read_u16(0x1e41c60+8));
            v0=!m.read_u32(0x1e497e0) && m.read_u32(0x1e41c60);return;
        case 0x1600f8:throw std::runtime_error("Name editor requires private input owner 0x001600f8");
        case 0x151f10:
            // The file's original ownership ends here. Its native fixed
            // allocation remains reserved for the lifetime of the session.
            if(u32(a0)!=m.read_u32(arena+4))throw std::runtime_error("Unexpected name input file release");
            return;
        default:throw std::runtime_error("Unknown name input source boundary");
        }
    }
};
#include "name_constructor_blocks.hpp"
std::string name_bytes(const GuestMemory& m,u32 p,unsigned limit){
    std::string value;
    for(unsigned i=0;i<limit && m.read_u8(p+i);++i)value+=char(m.read_u8(p+i));
    return value;
}
void gray_palette(GuestMemory& m,u32 font){ // 16AA98 -> 16A9F0.
    set_font_colors(m,font,{128,128,128});
}
void release_task(GuestMemory& m,u32 task) {
    if(!task)return;
    m.write_u32(task+4,1); // 179C80.
}
void commit_draft(GuestMemory& m,u32 manager,u32 editor,const std::string& draft){
    if(draft.size()>12 || draft.size()%2)throw std::runtime_error("Invalid original name byte count");
    const auto script=m.read_u32(manager+0x38),slot=m.read_u32(editor+8),name=script+0xe4+slot*16;
    for(u32 i=0;i<draft.size();++i)m.write_u8(name+i,std::uint8_t(draft[i]));
    m.write_u8(name+u32(draft.size()),0);
    (void)invoke_script_data(m,0x10d4c8,script,slot,name);
}
std::string draft_for(const GuestMemory& m,u32 manager,u32 editor){
    return name_bytes(m,m.read_u32(manager+0x38)+0xe4+16*m.read_u32(editor+8),12);
}
void add_source_character(GuestMemory& m,u32 manager,u32 editor,std::uint16_t code){ // 11B100.
    auto draft=draft_for(m,manager,editor);
    if(draft.size()==12)draft.resize(10);
    if(code>>8){draft+=char(code>>8);if((code&255)!=0)draft+=char(code);}
    commit_draft(m,manager,editor,draft);
    m.write_u32(editor+0x2c,std::min(5u,m.read_u32(editor+0x2c)+1));
}
void erase_source_character(GuestMemory& m,u32 manager,u32 editor){ // 11B1B0.
    auto draft=draft_for(m,manager,editor);
    if(draft.empty())return;
    draft.resize(draft.size()-2);commit_draft(m,manager,editor,draft);m.write_u32(editor+0x2c,u32(draft.size()/2));
}
void name_input(GuestMemory& m,u32 manager,ExecutionServices* s){
    const auto control=m.read_u32(manager+0x34);
    if(!m.read_u32(control))return;
    const auto editor=m.read_u32(control+8);
    if(editor!=m.read_u32(name_editor_cell))throw std::runtime_error("11AC10 requires original answer keyboard handler");
    const auto confirm=m.read_u32(editor+0x4c),slot=m.read_u32(editor+8);
    // 11AC10 dispatches gameplay input and presents this dedicated source
    // grid each tick. The native frontend paints NameEntryView's characters.
    const auto font=m.read_u32(manager+0x3c),gfx=m.read_u32(m.read_u32(editor+28)+44);
    (void)run_vm_context(m,0x16a830,font,0,0,0,s);gray_palette(m,font);
    for(const auto off:{12,16,20,0x120})m.write_u32(gfx+off,0);
    auto edges=m.read_u32(0x1e497e0)?0:choice_device_edges(m,0x1e41c60);
    const int point=s && s->choice_input?s->choice_input->name_index:-1;
    const bool clicked=point>=0 && s->choice_input->name_confirm;
    if(m.read_u32(editor+0x48)){ // 11C800.
        if(point==0 || point==1){m.write_u32(confirm+4,point);if(clicked)edges|=0x2000;}
        const auto focus=m.read_u32(confirm+4);
        if(edges&0x6000){
            const bool accept=(edges&0x2000) && !focus;
            (void)invoke_recovered(m,0x16cc38,0,0,0,0,s);
            (void)invoke_recovered(m,0x1b15f0,(edges&0x2000)?2:3,60,0,0,s);
            m.write_u32(editor+0x48,0);
            if(accept){
                release_task(m,m.read_u32(editor+28));release_task(m,m.read_u32(editor+32));
                m.write_u32(control,0);m.write_u32(manager+0x40,m.read_u32(control+4));
                gray_palette(m,m.read_u32(manager+0x3c));
                (void)invoke_recovered(m,0x1114f8,manager,0,0,0,s);
            }else{
                m.write_u32(m.read_u32(m.read_u32(editor+32)+44),1);
                m.write_u32(m.read_u32(editor+28)+24,0x185408);
                for(const auto off:{0x68,0x54,0x50,0x60,100})m.write_u32(editor+off,0);
            }
        }else{
            if(edges&0x8050){
                m.write_u32(confirm+4,!focus);(void)invoke_recovered(m,0x1b15f0,4,60,0,0,s);
            }
            // 16CC50 -> 16C898 moves the existing type-2 confirmation pointer.
            const auto arrow=0x1e44200+2*188;
            m.write_u32(arrow+16,std::bit_cast<u32>(248.0f));
            m.write_u32(arrow+20,std::bit_cast<u32>(m.read_u32(confirm+4)?294.0f:260.0f));
        }
        return;
    }
    if(edges&0xc00){
        const auto n=m.read_u32(editor+0x58),old=m.read_u32(editor+0x50);
        m.write_u32(editor+0x50,(edges&0x800)?(old+1)%n:(old+n-1)%n);
        for(const auto off:{0x68,0x54,0x60,100})m.write_u32(editor+off,0);
    }
    NameRegisters navigation(m,s);navigation.a0=editor;name_11b930(navigation);
    const auto group=m.read_u32(editor+0x5c)+8*m.read_u32(editor+0x50);
    const auto first=m.read_u32(editor+0x54);
    if(point>=0 && u32(point)/15>=first && u32(point)/15<first+8 && u32(point)/15<m.read_u32(group) &&
       m.read_u8(m.read_u32(group+4)+(u32(point)/15)*46+30+u32(point)%15)!=' '){
        m.write_u32(editor+0x60,u32(point)%15);m.write_u32(editor+100,u32(point)/15-first);
        m.write_u32(editor+0x68,u32(point)%15);if(clicked)edges|=0x2000;
    }
    if(edges&0x2000){
        const auto row=m.read_u32(editor+100)+first,col=m.read_u32(editor+0x60);
        if(row>=m.read_u32(group) || col>=15)throw std::runtime_error("Original 11B100 cursor outside grid");
        const auto code=m.read_u16(m.read_u32(group+4)+row*46+col*2);
        add_source_character(m,manager,editor,code);
    }else if(edges&0x4000){
        erase_source_character(m,manager,editor);
    }else if(edges&0x1000){
        if(draft_for(m,manager,editor).empty()){
            const auto draft=name_bytes(m,editor+12,12);commit_draft(m,manager,editor,draft);
            m.write_u32(editor+0x2c,std::min(5u,u32(draft.size()/2)));
        }
        m.write_u32(confirm+16,m.read_u32(editor+4));m.write_u32(confirm+12,slot);
        m.write_u32(confirm+8,m.read_u32(editor+28));m.write_u32(confirm+4,1);
        m.write_u32(m.read_u32(m.read_u32(editor+32)+44),0);
        m.write_u32(m.read_u32(editor+28)+24,0x1858c8);
        (void)invoke_recovered(m,0x16cbf8,248,288,0,0,s);m.write_u32(editor+0x48,1);
    }
}
}
void install_name_entry(GuestMemory& m,u32 manager,std::span<const std::uint8_t> bytes){
    if(!manager || m.read_u32(manager+0x34) || m.read_u32(arena) || bytes.empty() || bytes.size()>8192)
        throw std::runtime_error("Invalid new-game source name entry state");
    GuestMemory::Transaction tx(m);
    m.write_u32(arena,arena+16);
    const auto data=allocate_name_data(m,u32(bytes.size()));
    m.write_bytes(data,bytes);m.write_u32(arena+4,data);
    m.write_u32(0x238ab0,data);m.write_u32(0x238ab4,u32(bytes.size()));
    const auto controller=allocate_name_data(m,12);
    m.write_u32(manager+0x34,controller);
    NameRegisters state(m,nullptr);state.a0=controller;name_11a688(state);
    m.write_u32(arena+8,allocate_name_data(m,10*0x150));
    tx.commit();
}
void retire_name_editor_tasks(GuestMemory& m){
    const auto tasks=m.read_u32(0x2388bc);
    if(!tasks)return;
    for(u32 i=23;i<=32;++i){
        const auto task=tasks+i*48;
        if(!m.read_u32(task) || !m.read_u32(task+4))continue;
        const auto cleanup=m.read_u32(task+32);
        if(cleanup!=0x185978 && cleanup!=0x185b40)continue;
        // Both source task destructors release only the private allocation.
        // The corresponding native reserved payload is reusable with this slot.
        m.write_u32(task+4,0);m.write_u32(task,0); // 179CC0 after the callback.
    }
}
std::uint32_t name_task_payload(GuestMemory& m,u32 task,u32 bytes){
    const auto table=m.read_u32(0x2388bc);
    if(!table || task<table+23*48 || task>table+32*48 || (task-table)%48 ||
       m.read_u32(task+8)!=3 || (bytes!=0x144 && bytes!=0x30) || !m.read_u32(arena+8))
        throw std::runtime_error("Invalid name editor task allocation");
    return m.read_u32(arena+8)+((task-table)/48-23)*0x150;
}
static bool answer_editor(const GuestMemory& m,u32 editor){
    if(!editor)return false;
    const auto table=m.read_u32(editor);
    return table==0x2236d0 || table==0x223720 || table==0x223748;
}
static std::string answer_cell(const GuestMemory& m,unsigned index){
    // 11CD78 / 11D208 draw six rows, each with 15 two-byte glyphs and a separator.
    const u32 text=0x229678+(index/15)*31+(index%15)*2;
    return {char(m.read_u8(text)),char(m.read_u8(text+1))};
}
bool point_at_answer_cell(GuestMemory& m,u32 manager,int index){
    if(index<0 || index>=90 || !manager)return false;
    const auto ctrl=m.read_u32(manager+0x34);
    if(!ctrl || !m.read_u32(ctrl) || m.read_u32(manager+0x40)!=m.read_u32(0x235f5c))return false;
    const auto editor=m.read_u32(ctrl+8);
    if(!answer_editor(m,editor) || m.read_u32(editor+0x48) || answer_cell(m,index)=="\x81\x40")return false;
    m.write_u32(editor+0x50,index%15);m.write_u32(editor+0x54,index/15);return true;
}
NameEntryView name_entry_view(const GuestMemory& m,u32 manager){
    NameEntryView v;
    if(!manager)return v;
    const auto ctrl=m.read_u32(manager+0x34);
    if(!ctrl || !m.read_u32(ctrl) || m.read_u32(manager+0x40)!=m.read_u32(0x235f5c))return v;
    const auto e=m.read_u32(ctrl+8);if(!e || (e!=m.read_u32(name_editor_cell) && !answer_editor(m,e)))return v;
    v.open=true;v.slot=m.read_u32(e+8);v.page=m.read_u32(e+0x50);
    v.confirming=m.read_u32(e+0x48)!=0;
    const auto script=m.read_u32(manager+0x38);
    v.draft_cp932=name_bytes(m,script+0xe4+16*v.slot,12);
    v.confirm_focus=m.read_u32(m.read_u32(e+0x4c)+4);
    if(answer_editor(m,e)){
        v.focus=m.read_u32(e+0x54)*15+m.read_u32(e+0x50);
        for(unsigned i=0;i<90;++i){
            const auto text=answer_cell(m,i);
            v.cells.push_back({i,i%15,i/15,text,text=="\x81\x40"?' ':'+'});
        }
        return v;
    }
    if(v.page>=m.read_u32(e+0x58))throw std::runtime_error("Invalid 11BE28 grid group");
    const auto descriptor=m.read_u32(e+0x5c)+8*v.page;
    const auto rows=m.read_u32(descriptor),first=m.read_u32(e+0x54),cells=m.read_u32(descriptor+4);
    v.focus=(first+m.read_u32(e+100))*15+m.read_u32(e+0x60);
    for(u32 row=first;row<rows && row<first+8;++row){
        for(u32 x=0;x<15;++x){
            const auto code=m.read_u16(cells+row*46+x*2);
            const auto tag=char(m.read_u8(cells+row*46+30+x));
            std::string text;if(code){text+=char(code>>8);text+=char(code);}
            v.cells.push_back({row*15+x,x,row-first,std::move(text),tag});
        }
    }
    return v;
}
bool has_name_entry(u32 e){return e==0x11a688 || e==0x11b100 || e==0x11b1b0 || e==0x11b930 ||
    e==0x12ebf8 || e==0x120c88 || e==0x120cb8 || e==0x120ce8 || e==0x11ac10;}
u64 invoke_name_entry(GuestMemory& m,u32 entry,u32 self,u64 arg,ExecutionServices* s){
    if(entry==0x120c88){name_input(m,u32(arg),s);return 1;}
    if(entry==0x11ac10){
        const auto manager=m.read_u32(owner_pointer),controller=m.read_u32(manager+0x34);
        if(!controller || m.read_u32(controller+8)!=self)throw std::runtime_error("11AC10 received another name editor");
        name_input(m,manager,s);return 0;
    }
    if(entry==0x120cb8 || entry==0x120ce8){
        const auto helper=u32(arg),off=entry==0x120cb8?0x4cu:0x58u;
        return invoke_recovered(m,m.read_u32(m.read_u32(helper)+off),helper,self,0,0,s);
    }
    if(entry==0x11a688){NameRegisters state(m,s);state.a0=self;name_11a688(state);return state.v0;}
    if(entry==0x11b930){NameRegisters state(m,s);state.a0=self;name_11b930(state);return state.v0;}
    if(entry==0x11b100){add_source_character(m,m.read_u32(owner_pointer),self,std::uint16_t(arg));return 0;}
    if(entry==0x11b1b0){erase_source_character(m,m.read_u32(owner_pointer),self);return 0;}
    if(entry!=0x12ebf8)throw std::invalid_argument("Unknown name input routine");
    return run_vm_context(m,entry,self,arg,0,0,s);
}
}
