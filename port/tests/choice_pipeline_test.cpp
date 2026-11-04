#include "../core/choice_pipeline.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdint>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
using namespace kx3;
constexpr std::uint32_t manager=0x1e16a40, choice=0x1e11d80;
unsigned checks=0;
void check(bool yes,const char* message) {++checks;if(!yes)throw std::runtime_error(message);}
float real(std::uint32_t raw) {return std::bit_cast<float>(raw);}

// A headless, logical presentation model, not a GUI or an original-machine
// oracle. It starts from original pool nodes and applies the actual range/ID
// events. Source callbacks are intentionally unavailable in this fixture.
struct HeadlessPresentation final : ChoiceServices {
    struct Glyph {std::array<unsigned,3> rgb;float current,step;};
    std::array<std::vector<Glyph>,2> nodes;
    std::vector<ChoiceEffect> tasks;
    std::array<unsigned,3> font_primary{},font_secondary{};
    float pointer_x=0,pointer_y=0,font_x=0,font_y=0;
    bool pointer_visible=true;
    explicit HeadlessPresentation(const GuestMemory& m) {
        const auto font=m.read_u32(manager+0x3c);
        for(unsigned channel=0;channel<2;++channel) {
            const auto pool=m.read_u32(m.read_u32(font+8+channel*4));
            const auto count=m.read_u32(pool+4),data=m.read_u32(pool+8);
            check(count<=m.read_u32(pool),"original glyph pool count exceeds capacity");
            for(unsigned i=0;i<count;++i) {
                const auto p=data+i*56; // 169C40: index * 0x38 + pool[2].
                nodes[channel].push_back({{m.read_u8(p),m.read_u8(p+1),m.read_u8(p+2)},
                                          real(m.read_u32(p+4)),real(m.read_u32(p+8))});
            }
        }
    }
    bool supports_source(std::uint32_t) const override {return false;}
    std::uint64_t call_source(GuestMemory&,std::uint32_t,std::span<const std::uint64_t>) override {
        throw std::runtime_error("headless fixture has no external source callback");
    }
    bool supports_effect(ChoiceEffectKind) const override {return true;}
    bool glyph_animation_pending() const override {
        for(const auto& channel:nodes)for(const auto& n:channel)
            if(n.step!=0 && n.current!=(n.step>0?128.0f:0.0f))return true;
        return false;
    }
    void publish(const ChoiceUpdate& update) {
        for(const auto& e:update.pending_effects) {
            switch(e.kind) {
            case ChoiceEffectKind::glyph_color:
            case ChoiceEffectKind::glyph_step:
            case ChoiceEffectKind::glyph_current:
                for(int i=e.first;i<=e.last_inclusive;++i) {
                    if(i<0 || std::size_t(i)>=nodes.at(e.channel).size())
                        throw std::runtime_error("published range exceeds original live glyph pool");
                    auto& n=nodes[e.channel][i];
                    if(e.kind==ChoiceEffectKind::glyph_color)n.rgb=e.rgb;
                    if(e.kind==ChoiceEffectKind::glyph_step)n.step=e.value;
                    if(e.kind==ChoiceEffectKind::glyph_current)n.current=e.value;
                }
                break;
            case ChoiceEffectKind::pointer_move:pointer_x=e.x;pointer_y=e.y;break;
            case ChoiceEffectKind::pointer_hide:if(e.channel==2)pointer_visible=false;break;
            case ChoiceEffectKind::font_position:font_x=e.x;font_y=e.y;break;
            case ChoiceEffectKind::font_palette:font_primary=e.rgb;font_secondary=e.secondary_rgb;break;
            case ChoiceEffectKind::task_restore:
            case ChoiceEffectKind::task_retire:
            case ChoiceEffectKind::task_callbacks:
            case ChoiceEffectKind::task_pause:tasks.push_back(e);break;
            }
        }
    }
    void glyph_tick() {
        for(auto& channel:nodes)for(auto& n:channel) {
            if(n.step==0)continue;
            n.current=n.current+n.step;
            if(n.current<=0) {n.current=0;n.step=0;}
            else if(n.current>=128) {n.current=128;n.step=0;}
        }
    }
};
std::vector<std::uint8_t> image(const GuestMemory& m) {
    auto b=m.bytes(0,GuestMemory::size);return {b.begin(),b.end()};
}
template<class F> void must_fail_unchanged(GuestMemory& m,F f,const char* text) {
    const auto before=image(m);bool failed=false;
    try {f();}catch(const std::exception& e) {failed=std::string(e.what()).find(text)!=std::string::npos;}
    check(failed,"expected explicit unresolved/scope error");
    check(std::equal(before.begin(),before.end(),m.bytes(0,GuestMemory::size).begin()),
          "failed step leaked guest writes");
    check(!m.transaction_active(),"transaction did not release");
}
}

int main() {
    try {
        _setmode(_fileno(stdin),_O_BINARY);
        std::vector<std::uint8_t> original(GuestMemory::size);
        std::cin.read(reinterpret_cast<char*>(original.data()),original.size());
        if(std::cin.gcount()!=std::streamsize(original.size()))throw std::runtime_error("expected exact EE RAM on stdin");
        GuestMemory m;m.write_bytes(0,original);
        check(m.read_u32(0x235e40)==manager && m.read_u32(manager+8)==choice,"slot7 manager binding mismatch");
        check(m.read_u32(choice+0x168)==0 && m.read_u32(choice+4)==3,"original choice not A of3");
        check(m.read_u32(choice+8)==2,"preview index differs from focus");
        check(m.read_u32(0x1e4ab7c)==0 && m.read_u32(0x1e4ab80)==0,"fixture callbacks changed");
        HeadlessPresentation frontend(m);
        check(frontend.nodes[0].size()==135 && frontend.nodes[1].empty(),"slot7 glyph counts differ");
        {
            GuestMemory readback;readback.write_bytes(0,original);HeadlessPresentation view(readback);
            const auto state=readback.read_u32(manager+0x38),helper=readback.read_u32(manager+4);
            auto up=choice_readback_gate_atomic(readback,manager,ChoiceInput{.edges=0x10,.held=0x10},view);
            check(up.readback_entered && up.handler_return==1,"Up at A did not enter original readback");
            check(readback.read_u32(state+0xd0)==18 && readback.read_u32(state+0xd4)==2835,"wrong original backward history target");
            check(readback.read_u32(manager+0x40)==readback.read_u32(0x235f24),"original11F530 context not installed");
            check(readback.read_u32(state+0x148)==1 && readback.read_u32(0x238684)==1,"history and variables not pushed");
            check(readback.read_u32(helper+8)==18 && readback.read_u32(helper+12)==2839,"saved original choice position lost");
            check(readback.read_u32(helper+0x18)==0 && readback.read_u32(helper+0x28)==20,"readback enter/repeat state wrong");
            const auto live=readback.read_u32(state+0x138),saved=readback.read_u32(state+0x13c);
            const auto bytes=readback.read_u32(state+0x134)*8;
            check(std::equal(original.begin()+live,original.begin()+live+bytes,readback.bytes(saved,bytes).begin()),"history snapshot differs from original live history");
            check(std::equal(original.begin()+0x238af0,original.begin()+0x238ef0,readback.bytes(0x238ef0,1024).begin()),"variable snapshot differs");
            view.publish(up);
            check(view.font_primary==std::array<unsigned,3>{112,64,0} && !view.pointer_visible,"readback presentation contract incomplete");
        }
        const auto script=m.read_u32(manager+0x38),cursor=m.read_u32(script+0xd8);
        auto no_input=choice_context_atomic(m,manager,{},frontend);
        check(no_input.pending_effects.empty() && no_input.focus==0,"no input mutated focus/effects");
        check(std::equal(original.begin(),original.end(),m.bytes(0,GuestMemory::size).begin()),"no input changed RAM");

        check(choice_readback_eligible(m),"original134AF0 slot7 eligibility should be true");
        auto down_gate=choice_readback_gate_atomic(m,manager,ChoiceInput{.edges=0x40,.held=0x40},frontend);
        check(!down_gate.readback_entered && down_gate.handler_return==0,"nonboundary Down did not pass manager gate");

        auto down=choice_context_atomic(m,manager,ChoiceInput{.edges=0x40,.held=0x40},frontend);
        check(down.focus==1 && down.pending_effects.size()==5,"Down did not follow source focus chain");
        check(frontend.nodes[0][81].rgb!=std::array<unsigned,3>{128,64,64},"effects published before commit acknowledgement");
        frontend.publish(down);
        check(frontend.nodes[0][81].rgb==std::array<unsigned,3>{128,64,64},"B not highlighted");
        check(frontend.nodes[0][59].rgb!=std::array<unsigned,3>{128,64,64},"A remained focused color");
        check(frontend.pointer_x==14 && frontend.pointer_y==198,"original pointer coordinates wrong");
        check(m.read_u32(script+0xd8)==cursor && m.read_u32(choice+8)==2,"navigation changed preview/script cursor");

        auto mouse=choice_context_atomic(m,manager,ChoiceInput{.mouse_index=2},frontend);frontend.publish(mouse);
        check(mouse.focus==2 && frontend.pointer_y==278,"mouse did not share source focus navigation");
        auto clamp=choice_context_atomic(m,manager,ChoiceInput{.edges=0x40},frontend);frontend.publish(clamp);
        check(clamp.focus==2,"context-local Down should clamp (manager readback gate is separate)");
        auto wrap=choice_context_atomic(m,manager,ChoiceInput{.edges=0x8000},frontend);frontend.publish(wrap);
        check(wrap.focus==0,"0x8000 did not wrap to A");
        auto ignored=choice_context_atomic(m,manager,ChoiceInput{.edges=0x40a0},frontend);
        check(ignored.focus==0 && ignored.pending_effects.empty(),"left/right/Cross incorrectly changed ordinary choice");
        m.write_u32(0x1e4ab8c,0xdeadbeef);
        must_fail_unchanged(m,[&]{choice_readback_gate_atomic(m,manager,ChoiceInput{.edges=0x10,.held=0x10},frontend);},"0xdeadbeef");
        m.write_u32(0x1e4ab8c,0);
        must_fail_unchanged(m,[&]{choice_context_atomic(m,manager,ChoiceInput{.mouse_index=3},frontend);},"outside original options");

        auto begin=choice_context_atomic(m,manager,ChoiceInput{.mouse_index=1,.mouse_confirm=true},frontend);
        check(begin.confirming && !begin.transferred && begin.focus==1,"confirm did not start source transition");
        check(m.read_u32(manager+0x40)==m.read_u32(0x235f0c),"confirm singleton not installed");
        frontend.publish(begin);
        check(!frontend.pointer_visible,"pointer not hidden on confirmation");
        check(frontend.nodes[0][59].step==-8 && frontend.nodes[0][105].step==-8 && frontend.nodes[0][81].step==0,
              "nonfocus source ranges did not receive -8 step");
        check(frontend.glyph_animation_pending(),"fade acknowledged before logical glyph completion");
        for(unsigned tick=0;tick<16;++tick) {
            auto wait=choice_context_atomic(m,manager,{},frontend);
            check(wait.confirming && !wait.transferred && wait.pending_effects.empty(),"confirm progressed before renderer ready");
            frontend.glyph_tick();
        }
        check(!frontend.glyph_animation_pending(),"original 128/-8 fade not ready after16 renderer ticks");
        check(frontend.nodes[0][59].current==0 && frontend.nodes[0][105].current==0 && frontend.nodes[0][81].current==128,
              "fade altered wrong glyphs");
        // Fault injection makes a genuinely required progress callback unknown.
        // Preserve exact original bytes after the atomic rollback check.
        const auto old_force=m.read_u32(script+0x180);
        m.write_u32(script+0x180,1);m.write_u32(0x1e4ab88,0xdeadbeef);
        must_fail_unchanged(m,[&]{choice_context_atomic(m,manager,{},frontend);},"0xdeadbeef");
        check(m.read_u32(script+0xd8)==cursor,"failed callback consumed source cursor");
        check(m.read_u32(manager+0x40)==m.read_u32(0x235f0c),"failed callback escaped confirm context");
        m.write_u32(script+0x180,old_force);m.write_u32(0x1e4ab88,0);
        auto done=choice_context_atomic(m,manager,{},frontend);frontend.publish(done);
        check(done.transferred && !done.confirming,"original normal transfer did not finish");
        check(m.read_u32(manager+0x40)==m.read_u32(0x235f3c),"default source context not restored");
        check(m.read_u32(script+0xd0)==18 && m.read_u32(script+0xd8)!=cursor,"B target selector/cursor not installed");
        check(m.read_u32(m.read_u32(manager+0x28)+0x14)==1,"source11A380 state flag missing");
        check(frontend.nodes[0][81].current==0,"confirmed option current not cleared");

        // Source15F168 cache on an isolated test device. Original state untouched.
        constexpr auto device=0x1000u;
        m.write_u16(device+0xba,0x10);m.write_u16(device+0xb8,0x50);m.write_u32(device+0xb4,1);
        check(choice_device_edges(m,device)==0x40,"edge computation incorrect");
        check(choice_device_edges(m,device)==0x40 && m.read_u32(device+0xb4)==0,"second sample consumed cached edge");
        m.write_u16(device+0xb8,0);m.write_u32(device+0xb4,1);
        check(choice_device_edges(m,device)==0,"release generated false press edge");
        std::cout << "{\"status\":\"passed\",\"checks\":" << checks
                  << ",\"original_glyphs\":135,\"choice_count\":3,\"fade_render_ticks\":16,"
                     "\"transfer_completed\":true,\"readback_up_entered\":true,\"forward_readback_complete\":false,"
                     "\"kind\":\"source-bound-headless-contract-test-not-machine-oracle\"}\n";
        return 0;
    }catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}
