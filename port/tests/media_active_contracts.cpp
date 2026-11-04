// Explicit synthetic platform/guest contract tests. These are NOT machine-code
// oracle cases and do not claim that synthetic pixels decode an original asset.
#include "../core/media_active.hpp"
#include "../core/guest_memory.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <stdexcept>

using namespace kx3;
namespace {
unsigned passed = 0;
void check(bool value) { if (!value) throw std::runtime_error("contract assertion failed"); ++passed; }
template<class F> void fails(F call) { bool failed = false; try { call(); } catch (const std::exception&) { failed = true; } check(failed); }
void string(GuestMemory& m, std::uint32_t at, const std::string& s) {
    for (unsigned i = 0; i < s.size(); ++i) m.write_u8(at+i, static_cast<std::uint8_t>(s[i]));
    m.write_u8(at+static_cast<std::uint32_t>(s.size()),0);
}
void descriptor(GuestMemory& m, const std::vector<std::string>& names) {
    m.write_u16(0x1f00000,static_cast<std::uint16_t>(names.size()));
    std::uint32_t cursor=0x1f00002;
    for(const auto& n:names){string(m,cursor,n);cursor+=static_cast<std::uint32_t>(n.size()+1);}
}
class FixtureServices final : public MediaActiveServices {
public:
    std::map<std::string,std::uint32_t> sizes{{"MOVIE/my0000.ipu",6068},{"MOVIE/sy0000b.ipu",100},{"MOVIE/a.m2v",200},{"a.ogg",300}};
    bool fail_preload=false, malformed=false, retained=true;
    unsigned calls=0, discarded=0;
    mutable unsigned retention_queries=0;
    std::uint32_t source_file_size(const std::string& s) const override {
        const auto i=sizes.find(s); return i==sizes.end()?0:i->second;
    }
    bool sound_retention_flag(std::uint32_t) const override {++retention_queries;return retained;}
    MediaPrepareReceipt preload(const SourceResourcePlan& p) override {
        ++calls;if(fail_preload)throw std::runtime_error("deliberate unavailable codec");
        MediaPrepareReceipt r;r.prepared_generation=1;r.current_presentation_unchanged=true;
        r.prepared_bgm=p.audio.prepare_bgm;r.retained_sound_ids=p.audio.retain_ids;
        for(const auto& a:p.assets){MediaAssetReceipt x;x.virtual_name=a.virtual_name;
            x.source_sha256=std::string(64,'a');x.source_size_bytes=a.source_size_bytes;x.decoded_kind=a.required_kind;
            x.width=2;x.height=2;x.frame_count=1;x.decoded_bytes=16;x.sample_count=4;r.assets.push_back(x);}
        if(malformed)r.assets[0].decoded_bytes=0;return r;
    }
    void discard_prepared(std::uint64_t) noexcept override {++discarded;}
};
void load_elf(GuestMemory& m,const char* path){
    std::ifstream f(path,std::ios::binary);if(!f)throw std::runtime_error("ELF missing");
    std::vector<std::uint8_t> b((std::istreambuf_iterator<char>(f)),{});
    const auto u16=[&](std::size_t a){return unsigned(b.at(a))|unsigned(b.at(a+1))<<8;};
    const auto u32=[&](std::size_t a){return std::uint32_t(u16(a))|std::uint32_t(u16(a+2))<<16;};
    check(b.size()>52&&b[0]==127&&b[1]=='E'&&u16(18)==8);
    for(unsigned i=0;i<u16(44);++i){auto at=u32(28)+i*u16(42);if(u32(at)!=1)continue;
        const auto off=u32(at+4),va=u32(at+8),size=u32(at+16);
        m.write_bytes(va,std::span<const std::uint8_t>(b).subspan(off,size));}
}
}
int main(int argc,char** argv){try{
    if(argc!=2)throw std::runtime_error("usage: media_active_contracts original-ELF");
    GuestMemory m;load_elf(m,argv[1]);FixtureServices services;
    string(m,0x1f01000,"fixture");descriptor(m,{"my0000.ipu"});
    MediaRequest request{0x137578,0x1f00000,0x1f01000,{'f','i','x','t','u','r','e'},0,1,0};
    auto before=std::vector<std::uint8_t>(m.bytes(0,GuestMemory::size).begin(),m.bytes(0,GuestMemory::size).end());
    auto plan=plan_active_media(m,request,services);
    check(plan.assets.size()==1&&plan.primary_virtual_name=="MOVIE/my0000.ipu");
    check(plan.assets[0].source_size_bytes==6068&&plan.assets[0].source_type==6);
    check(std::equal(before.begin(),before.end(),m.bytes(0,GuestMemory::size).begin()));
    check(services.calls==0);
    SourceMediaActiveBackend backend(services);
    services.fail_preload=true;fails([&]{backend.execute_active(m,request);});
    check(std::equal(before.begin(),before.end(),m.bytes(0,GuestMemory::size).begin()));
    services.fail_preload=false;services.malformed=true;fails([&]{backend.execute_active(m,request);});
    check(services.discarded==1);
    check(std::equal(before.begin(),before.end(),m.bytes(0,GuestMemory::size).begin()));
    services.malformed=false;
    auto receipt=services.preload(plan);validate_media_receipt(plan,receipt);++passed;
    receipt.current_presentation_unchanged=false;fails([&]{validate_media_receipt(plan,receipt);});
    receipt.current_presentation_unchanged=true;receipt.assets[0].source_size_bytes++;fails([&]{validate_media_receipt(plan,receipt);});
    receipt=services.preload(plan);receipt.assets[0].virtual_name="wrong";fails([&]{validate_media_receipt(plan,receipt);});
    receipt=services.preload(plan);receipt.assets[0].source_sha256="not-source-sha";fails([&]{validate_media_receipt(plan,receipt);});
    // Success below uses an explicit synthetic platform fixture. Only semantic
    // field publication is tested; the root separately tests the real WIC cache.
    {GuestMemory::Transaction tx(m);backend.execute_active(m,request);tx.commit();}
    check(m.read_u32(0x238718)==1&&m.read_u32(0x23ba50+48)==6);
    check(m.read_u32(0x23ba50+52)==6068&&m.read_u32(0x23ba50+56)==0);
    descriptor(m,{"missing.ipu"});plan=plan_active_media(m,request,services);
    check(plan.assets[0].resolved_name=="sy0000b.ipu");
    descriptor(m,{"a.m2s"});plan=plan_active_media(m,request,services);
    check(plan.assets[0].resolved_name=="a.m2v"&&plan.assets[0].flags==3);
    descriptor(m,{"my0000.ipu","532011","a.ogg"});plan=plan_active_media(m,request,services);
    check(plan.assets[0].resolved_name=="532011"&&plan.assets[1].resolved_name=="a.ogg");
    check(plan.audio.prepare_bgm==std::vector<std::string>{"a.ogg"});
    check(plan.audio.retain_ids==std::vector<std::uint32_t>{532011});
    check(plan.audio.source_pool_ids==std::vector<std::uint32_t>{532011});
    const auto prior_queries=services.retention_queries;
    descriptor(m,{"my0000.ipu","4294967295"});plan=plan_active_media(m,request,services);
    check(plan.audio.retain_ids==std::vector<std::uint32_t>{0xffffffffu});
    check(plan.audio.source_pool_ids.empty()&&services.retention_queries==prior_queries);
    descriptor(m,{"532011"});fails([&]{plan_active_media(m,request,services);});
    descriptor(m,{"my0000.ipu"});m.write_u32(0x206250+0x5c8,1);fails([&]{plan_active_media(m,request,services);});
    m.write_u32(0x206250+0x5c8,0);request.token_bytes[0]='x';fails([&]{plan_active_media(m,request,services);});
    std::cout<<"{\"passed\":"<<passed<<",\"authority\":\"synthetic core/platform boundary contracts, not machine-code oracle\"}\n";
    return 0;
}catch(const std::exception& e){std::cerr<<e.what()<<" after "<<passed<<" checks\n";return 1;}}
