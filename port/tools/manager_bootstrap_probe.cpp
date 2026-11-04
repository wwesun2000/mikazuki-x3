#include "../core/manager_bootstrap.hpp"
#include "../core/choice_pipeline.hpp"
#include "../core/runtime.hpp"
#include <algorithm>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <set>

namespace {
using u32 = std::uint32_t;
using Bytes = std::vector<std::uint8_t>;
Bytes file_bytes(const char* path, std::size_t maximum) {
    std::ifstream f(path,std::ios::binary|std::ios::ate);
    if(!f || f.tellg()<0 || static_cast<std::size_t>(f.tellg())>maximum) throw std::runtime_error("Invalid bounded file");
    Bytes data(static_cast<std::size_t>(f.tellg()));
    f.seekg(0);
    if(!f.read(reinterpret_cast<char*>(data.data()), data.size())) throw std::runtime_error("Input read failed");
    return data;
}
void require(bool ok,const char* reason){if(!ok)throw std::runtime_error(reason);}
class ClosedDependencies final : public kx3::ChoiceServices {
public:
    bool supports_source(u32) const override { return false; }
    std::uint64_t call_source(kx3::GuestMemory&,u32,std::span<const std::uint64_t>) override {
        throw std::runtime_error("Cold dispatch reached an unavailable source service");
    }
    bool supports_effect(kx3::ChoiceEffectKind) const override { return false; }
    bool glyph_animation_pending() const override { throw std::runtime_error("Cold dispatch needs live glyph service"); }
};
}
int main(int argc,char** argv) {
    try {
        require(argc==5 || argc==6,"Usage: manager_bootstrap_probe original.elf original.sn4 heap_fill before.bin [after_first.bin]");
        const auto elf=file_bytes(argv[1],2*1024*1024), disk=file_bytes(argv[2],8*1024*1024);
        const auto font_path=std::filesystem::path(argv[2]).replace_extension(".fnt").string();
        const auto font=file_bytes(font_path.c_str(),8*1024*1024);
        require(elf.size()==1290132,"Unexpected source ELF size");
        const auto fill=std::stoul(argv[3]);require(fill<=255,"Invalid fill");
        kx3::GuestMemory m;
        m.write_bytes(0x100000,std::span(elf).subspan(0x1000,0x138648));
        const auto game=std::filesystem::path(argv[2]).stem().string();
        require(game=="sn4" || game=="sn4g" || game=="sn2","Unknown original scenario selection");
        m.write_u32(0x235b00,game=="sn4"?0u:game=="sn4g"?1u:2u);
        m.write_bytes(0x300000, Bytes(0xd00000,static_cast<std::uint8_t>(fill)));
        m.write_bytes(0x238af0, Bytes(1024, static_cast<std::uint8_t>(fill)));
        m.write_u32(0x238684,0x4567);
        ClosedDependencies services;
        std::optional<kx3::ReadyScenarioResource> slot{{disk,static_cast<u32>(disk.size())}};
        auto result=kx3::bootstrap_manager_dispatch(m,slot,0x300000,0x400000,0x400000,0x1000000,services,font,0x1500000);
        require(!slot && result.constructed_handlers==115 && result.null_handlers==22,"Factory/resource count mismatch");
        require(result.script.registration_index==4,"ScriptData registration is out of original order");
        auto read=[&](u32 address){return m.read_u32(address);};
        require(!read(0x238684)&&std::all_of(m.bytes(0x238af0,1024).begin(),m.bytes(0x238af0,1024).end(),
                [](auto value){return value==0;}),"Cold variable table/depth mismatch");
        const auto manager=result.manager, context=read(manager+0x40), script=read(manager+0x38);
        const auto cursor=read(script+0xd8);
        const auto opcode=m.read_u8(cursor);
        const auto handler=read(manager+0x5c+4*opcode);
        const auto source_target=read(read(handler)+0x3c);
        require(opcode==0x22 && read(context)==0x2239f0 && read(read(context)+4)==0x120308 &&
                read(read(context)+8)==0x1203e0 && source_target==0x12f8d8,"Incorrect initial source dispatch");
        std::set<u32> objects;
        for(u32 i=0;i<137;++i)if(const auto p=read(manager+0x5c+i*4))require(objects.insert(p).second,"Aliased handler object");
        require(objects.size()==115,"Wrong number of individually allocated handlers");
        const Bytes before(m.bytes(0,m.size).begin(),m.bytes(0,m.size).end());
        std::ofstream output(argv[4],std::ios::binary|std::ios::trunc);
        require(bool(output.write(reinterpret_cast<const char*>(before.data()),before.size())),"Could not write cold RAM evidence");
        output.close();
        bool completed=false;
        std::uint64_t first_result=0;
        std::string frontier;
        kx3::ExecutionServices execution;
        execution.choice=&services;
        try { first_result=kx3::step_script_atomic(m,manager,&execution); completed=true; }
        catch(const std::runtime_error& e) {frontier=e.what();}
        if(!completed) require(std::equal(before.begin(),before.end(),m.bytes(0,m.size).begin()),"Failed first opcode did not roll back all RAM");
        const auto final_cursor=read(script+0xd8);
        if(argc==6) {
            std::ofstream after(argv[5],std::ios::binary|std::ios::trunc);
            auto bytes=m.bytes(0,m.size);
            require(bool(after.write(reinterpret_cast<const char*>(bytes.data()),bytes.size())),"Could not write post-first-op RAM");
        }
        u32 steps=completed?1u:0u;
        bool yielded=completed && first_result!=0;
        u32 next_opcode=0;
        std::string next_frontier=frontier;
        while(completed && !yielded && steps<65536) {
            next_opcode=m.read_u8(read(script+0xd8));
            try { yielded=kx3::step_script_atomic(m,manager,&execution)!=0; ++steps; }
            catch(const std::runtime_error& e) { next_frontier=e.what(); break; }
        }
        std::cout<<"{\"manager\":"<<manager<<",\"context\":"<<context<<",\"script\":"<<script<<",\"registry\":"<<result.registry
            <<",\"handlers\":"<<objects.size()<<",\"null_slots\":"<<result.null_handlers<<",\"selector\":"<<result.script.selector
            <<",\"label_id\":"<<result.script.label_id<<",\"entry_offset\":"<<result.script.code_relative_offset<<",\"entry_cursor\":"<<cursor
            <<",\"opcode\":"<<u32(opcode)<<",\"handler\":"<<handler<<",\"handler_vtable\":"<<read(read(manager+0x5c+4*opcode))
            <<",\"source_target\":"<<source_target<<",\"first_opcode_completed\":"<<(completed?"true":"false")
            <<",\"first_call_frontier\":"<<std::quoted(frontier)<<",\"final_cursor\":"<<final_cursor
            <<",\"first_result\":"<<first_result<<",\"committed_steps\":"<<steps<<",\"yielded\":"<<(yielded?"true":"false")
            <<",\"walk_opcode\":"<<next_opcode<<",\"walk_frontier\":"<<std::quoted(next_frontier)<<"}\n";
        return 0;
    }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}
}
