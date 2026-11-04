#include "story_localization.hpp"
#include "../core/guest_memory.hpp"
#include <algorithm>
#include <bit>
#include <cmath>
#include <iomanip>
#include <map>
#include <sstream>
#include <string_view>

namespace kx3::platform {
namespace {
using u32=std::uint32_t;
struct Group {std::string_view id;unsigned primary,ruby;std::string_view zh,en;unsigned segments,count;bool semantic_cuts=false;};
struct Unit {u32 offset;unsigned code,group,ordinal,ruby;};
struct Segment {unsigned primary_end;std::string_view zh,en;};
struct Record {u32 offset,end;unsigned selector;};
struct DirectRecord {u32 offset,end,group,checksum,ordinal,ruby;};
struct NamePrefix {u32 offset,group;std::string_view zh,en;};
struct NameSentence {u32 site;std::string_view before,after,ending,final_before,final_after;};
struct ChartTitle {std::string_view table;unsigned index;std::string_view hex,ja,zh,en;};
struct Lookup {std::string_view program;unsigned source_size;std::span<const Group> groups;std::span<const Unit> units;
               std::span<const Segment> segments;std::span<const Record> records;std::span<const DirectRecord> direct;
               std::span<const NamePrefix> prefixes;std::span<const NameSentence> name_sentences;};
#include "story_locale_data.inc"

struct Exposure {
    unsigned index,primary=0,ruby=0;
    std::vector<bool> seen;
    int x=0,y=0,height=0;
    u32 first_node=0, opacity=0;
    unsigned leading_icon_width=0;
};
unsigned opacity(const GuestMemory& m,const TextGlyphEvent& e){
    if(!e.node_address)return 0;
    const auto a=std::bit_cast<float>(m.read_u32(e.node_address+4));
    return std::isfinite(a)?static_cast<unsigned>(std::clamp(a,0.0f,128.0f)*255/128):0;
}
unsigned text_rgb(const GuestMemory& m,u32 node){
    // The host font supplies a white glyph mask, as in the original FNT
    // atlas. The GS modulates it by the live node RGB with unity at 128.
    const auto channel=[&](unsigned i){return std::min(255u,m.read_u8(node+i)*255u/128u);};
    return (channel(0)<<16)|(channel(1)<<8)|channel(2);
}
std::string pending_id(u32 offset,bool in_file,const Lookup& data){
    std::ostringstream s;
    if(in_file){
        const auto records=data.records;
        auto it=std::upper_bound(std::begin(records),std::end(records),offset,[](u32 o,const Record& r){return o<r.offset;});
        if(it!=std::begin(records)){
            --it;if(offset<it->end){
                s<<data.program<<":"<<std::hex<<std::setfill('0')<<std::setw(2)<<it->selector<<":"<<std::setw(8)<<it->offset;
                return s.str();
            }
        }
    }
    s<<(in_file?"unbound-offset:":"runtime-address:")<<std::hex<<offset;
    return s.str();
}
// Keep UTF-8 scalar boundaries, including supplementary CJK characters.
std::string fragment(std::string_view text,unsigned count,unsigned total){
    if(!count || text.empty())return {};
    if(count>=total)return std::string(text);
    const auto leading=[](char ch){return (static_cast<unsigned char>(ch)&0xc0u)!=0x80u;};
    const size_t scalars=std::count_if(text.begin(),text.end(),leading);
    const size_t take=std::min(scalars-1,(scalars*count+total-1)/total);
    size_t seen=0,bytes=0;
    for(;bytes<text.size();++bytes)if(leading(text[bytes]) && seen++==take)break;
    return std::string(text.substr(0,bytes));
}
std::string translation(const Exposure& s,StoryLanguage lang,const Lookup& data){
    const auto& g=data.groups[s.index];const auto segments=data.segments;
    const auto whole=lang==StoryLanguage::english?g.en:g.zh;
    if(s.primary==g.primary && s.ruby==g.ruby)return std::string(whole);
    // A group without bilingual phrase alignment is published only after its
    // original members arrive. Never infer which later clause a pause reveals.
    std::string result;
    unsigned previous=0;
    for(const auto& part:std::span(segments).subspan(g.segments,g.count)){
        if(g.semantic_cuts){
            if(s.primary<part.primary_end || (part.primary_end==g.primary && s.ruby<g.ruby))break;
            result+=lang==StoryLanguage::english?part.en:part.zh;
            continue;
        }
        if(s.primary<=previous)break;
        auto visible=std::min(s.primary,part.primary_end)-previous;
        const auto length=part.primary_end-previous;
        if(part.primary_end==g.primary && s.ruby<g.ruby && visible==length)--visible;
        result+=fragment(lang==StoryLanguage::english?part.en:part.zh,visible,length);
        previous=part.primary_end;
    }
    return result;
}
}

std::string_view english_default_player_name(unsigned slot,std::string_view full_cp932){
    // CP932 defaults copied by the original script constructor from 235E30/235E38.
    if(slot==0 && full_cp932=="\x93\xa7")return "Toru";
    if(slot==1 && full_cp932=="\x90\x5e\x97\x9d")return "Mari";
    return {};
}

std::string_view localize_chart_title(std::string_view table,unsigned index,std::string_view raw,StoryLanguage lang){
    if(raw.empty())return {};
    for(const auto& title:chart_titles)if(title.table==table && title.index==index){
        if(raw.size()*2!=title.hex.size())return {};
        constexpr char hex[]="0123456789abcdef";
        for(std::size_t i=0;i<raw.size();++i){
            const auto byte=static_cast<unsigned char>(raw[i]);
            if(title.hex[2*i]!=hex[byte>>4] || title.hex[2*i+1]!=hex[byte&15])return {};
        }
        return lang==StoryLanguage::japanese?title.ja:lang==StoryLanguage::chinese?title.zh:title.en;
    }
    return {};
}

LocalizedPage localize_story_page(const GuestMemory& m,u32 script,StoryLanguage lang,
                                  std::span<const TextGlyphEvent> committed,std::string_view scenario){
    LocalizedPage page;
    const auto* lookup=scenario=="sn4g"?&sn4g::lookup:scenario=="sn4"?&sn4::lookup:scenario=="sn2"?&sn2::lookup:nullptr;
    if(!lookup)throw std::invalid_argument("Unknown original script for text lookup");
    const auto units=lookup->units;const auto groups=lookup->groups;
    const auto base=m.read_u32(script+4);
    std::vector<Exposure> exposure;
    std::vector<LocalizedLine> names;
    std::vector<std::pair<bool,std::size_t>> order;
    std::map<unsigned,std::size_t> last;
    const DirectRecord* cached=nullptr;
    bool verified=false;
    for(const auto& e:committed){
        const auto a=e.source.source_address;
        const bool in_file=a>=base && a-base<lookup->source_size;
        const auto offset=in_file?a-base:a;
        const auto found_unit=std::lower_bound(units.begin(),units.end(),offset,[](const Unit& unit,u32 o){return unit.offset<o;});
        const Unit* it=found_unit!=units.end() && found_unit->offset==offset?&*found_unit:nullptr;
        Unit direct_unit{};
        if(!it && in_file && lang!=StoryLanguage::japanese){
            if(!cached || offset<cached->offset || offset>=cached->end){
                const auto ranges=lookup->direct;
                const auto next=std::upper_bound(ranges.begin(),ranges.end(),offset,[](u32 o,const DirectRecord& r){return o<r.offset;});
                cached=next!=ranges.begin() && offset<(next-1)->end?&*(next-1):nullptr;
                verified=false;
                if(cached){
                    u32 checksum=2166136261u;
                    for(auto byte:m.bytes(base+cached->offset,cached->end-cached->offset))checksum=(checksum^byte)*16777619u;
                    verified=checksum==cached->checksum;
                }
            }
            if(verified && (lang!=StoryLanguage::english || !groups[cached->group].en.empty()) &&
               cached->ruby==unsigned(e.source.ruby) && offset>cached->offset && offset+1<cached->end-1 && (offset-cached->offset)%2==1){
                direct_unit={offset,e.source.source_unit,cached->group,cached->ordinal+(offset-cached->offset-1)/2,cached->ruby};
                it=&direct_unit;
            }
        }
        if(!in_file || !it || it->ruby!=unsigned(e.source.ruby) ||
           it->code!=e.source.source_unit || e.source.display_unit!=e.source.source_unit ||
           m.read_u8(a)!=(it->code>>8) || m.read_u8(a+1)!=(it->code&255)){
            bool choice_prefix=false;
            if(!in_file && !e.source.ruby && e.source.source_unit==e.source.display_unit){
                // 10D7D0's selector 32+n is the source's 22-byte synthesized
                // option prefix. Only suppress those two exact fullwidth units.
                for(unsigned i=0;i<10 && !choice_prefix;++i){
                    const auto block=m.read_u32(script+8+(32+i)*4);if(!block)continue;
                    const auto prefix=m.read_u32(block+0x430);
                    choice_prefix=(a==prefix+9 && e.source.source_unit==0x8260+i) ||
                                  (a==prefix+11 && e.source.source_unit==0x8146);
                }
            }
            if(choice_prefix)continue;
            // 10D4C8 installs five live-name blocks at selectors 42..46.
            // Translate the sentence around these; the player's own name
            // comes from the actual committed characters in the original slot.
            bool name=false;
            if(!in_file && !e.source.ruby && e.source.source_unit==e.source.display_unit)
                for(unsigned slot=0;slot<5 && !name;++slot){
                    const auto block=m.read_u32(script+0xb0+4*slot);if(!block)continue;
                    const auto first=block+0x435;
                    if(a<first || a-first>=12 || (a-first)%2)continue;
                    const auto code=e.source.source_unit;
                    if(m.read_u8(a)!=(code>>8) || m.read_u8(a+1)!=(code&255))continue;
                    const auto id=std::string(scenario)+":player-name:"+std::to_string(slot);
                    if(order.empty() || !order.back().first || names.back().group_id!=id || a==first){
                        const auto site=e.source.insertion_site;
                        if(lang!=StoryLanguage::japanese && slot==1 && site>=base && site-base<lookup->source_size && m.read_u8(site)==0x0e){
                            const auto prefixes=lookup->prefixes;
                            const auto prefix=std::lower_bound(prefixes.begin(),prefixes.end(),site-base,
                                [](const NamePrefix& p,u32 o){return p.offset<o;});
                            if(prefix!=prefixes.end() && prefix->offset==site-base){
                                const auto text=lang==StoryLanguage::english?prefix->en:prefix->zh;
                                if(!text.empty()){
                                    order.emplace_back(true,names.size());
                                    names.push_back({std::string(groups[prefix->group].id)+":before-name",std::string(text),
                                        e.x,e.y,static_cast<int>(e.height),1,1,e.node_address,opacity(m,e),-1,text_rgb(m,e.node_address)});
                                }
                            }
                        }
                        order.emplace_back(true,names.size());
                        names.push_back({id,{},e.x,e.y,static_cast<int>(e.height),0,0,e.node_address,0,-1,text_rgb(m,e.node_address),true});
                        if(site>=base && site-base<lookup->source_size && m.read_u8(site)==0x0e)
                            names.back().insertion_offset=site-base;
                    }
                    auto& line=names.back();
                    std::string_view english;
                    size_t name_length=0;
                    if(lang==StoryLanguage::english && slot<2){
                        const auto bytes=m.bytes(script+0xe4+slot*16,13);
                        name_length=std::find(bytes.begin(),bytes.end(),0)-bytes.begin();
                        const std::string_view full(reinterpret_cast<const char*>(bytes.data()),name_length);
                        if(name_length && std::equal(bytes.begin(),bytes.begin()+name_length,m.bytes(first,name_length).begin()))
                            english=english_default_player_name(slot,full);
                    }
                    const auto pos=a-first;
                    if(english.empty() || pos>=name_length){
                        line.text+=char(code>>8);line.text+=char(code);
                    }else if(!e.node_address || opacity(m,e)){
                        // An English syllable is emitted only with its contributing live source glyph.
                        const auto begin=pos*english.size()/name_length;
                        const auto end=(pos+2)*english.size()/name_length;
                        line.text+=english.substr(begin,end-begin);
                    }
                    line.opacity=std::max(line.opacity,opacity(m,e));line.total_primary=++line.primary_units;
                    name=true;
                }
            if(name)continue;
            const auto id=pending_id(offset,in_file,*lookup);
            if(std::find(page.pending.begin(),page.pending.end(),id)==page.pending.end())page.pending.push_back(id);
            continue;
        }
        const auto& g=groups[it->group];
        if(g.semantic_cuts && !it->ruby && e.node_address && !opacity(m,e))continue;
        auto found=last.find(it->group);
        if(found==last.end() || (it->ordinal==0 && exposure[found->second].seen[0])){
            last[it->group]=exposure.size();
            order.emplace_back(false,exposure.size());
            exposure.push_back({it->group,0,0,std::vector<bool>(g.primary+g.ruby,false)});
        }
        auto& s=exposure[last.at(it->group)];
        if(s.seen[it->ordinal])continue;
        s.seen[it->ordinal]=true;
        if(it->ruby)++s.ruby;
        else{
            if(it->ordinal==0 || (!s.first_node && e.node_address)){s.x=e.x;s.y=e.y;s.height=e.height;s.first_node=e.node_address;}
            if(!it->ordinal && e.resource_atlas>=0 && g.id=="sn4g:11:000b0343" && it->code==0x81a0)
                s.leading_icon_width=e.width;
            s.opacity=std::max(s.opacity,opacity(m,e));
            while(s.primary<g.primary && s.seen[s.primary])++s.primary;
        }
    }
    if(lang!=StoryLanguage::japanese)for(const auto& [name,index]:order){
        if(name){page.lines.push_back(std::move(names[index]));continue;}
        const auto& s=exposure[index];
        if(!s.primary)continue;
        const auto& g=groups[s.index];auto text=translation(s,lang,*lookup);
        // The checklist square can also be drawn from original artwork in
        // a centered font. The artwork layer already draws that actual node.
        if(s.leading_icon_width && text.starts_with("□"))text.erase(0,std::string_view("□").size());
        if(!text.empty())page.lines.push_back({std::string(g.id),std::move(text),s.x+int(s.leading_icon_width),s.y,s.height,s.primary,g.primary,s.first_node,s.opacity,-1,text_rgb(m,s.first_node)});
    }
    if(lang==StoryLanguage::english && lookup && !lookup->name_sentences.empty()){
        // Keep the original name node (including a custom CP932 spelling and its
        // opacity). Only the completed suffix authorizes moving English words
        // in front of that name.
        for(std::size_t i=1;i+1<page.lines.size();++i){
            const auto& name=page.lines[i];
            if(!name.player_name_cp932 || !name.insertion_offset)continue;
            auto& before=page.lines[i-1];auto& after=page.lines[i+1];
            for(const auto& rule:lookup->name_sentences){
                if(rule.site==name.insertion_offset && rule.before==before.group_id && rule.after==after.group_id &&
                   after.primary_units==after.total_primary && after.text==rule.ending){
                    before.text=rule.final_before;after.text=rule.final_after;break;
                }
            }
        }
    }
    if(!committed.empty() && !page.lines.empty()){
        const auto manager=committed.front().source.manager;
        const auto ctx=m.read_u32(manager+0x40),method=m.read_u32(m.read_u32(ctx));
        if(method==0x11e748 || (ctx && ctx==m.read_u32(0x235f0c))){
            const auto choice=m.read_u32(manager+8),count=m.read_u32(choice+4),font=m.read_u32(manager+0x3c);
            if(count<=10 && m.read_u32(choice+12)==1){
                const auto pool=m.read_u32(m.read_u32(font+8)),base=m.read_u32(pool+8),live=m.read_u32(pool+4);
                int previous=-1;
                for(auto& line:page.lines){
                    if(line.first_node<base || (line.first_node-base)%56)continue;
                    const unsigned n=(line.first_node-base)/56;
                    if(n>=live)continue;
                    for(unsigned i=0;i<count;++i){
                        if(n<m.read_u32(choice+0xc8+4*i) || n>m.read_u32(choice+0xf0+4*i))continue;
                        line.option=static_cast<int>(i);
                        if(line.option!=previous)line.text=std::string(1,char('A'+i))+"  "+line.text;
                        previous=line.option;
                        break;
                    }
                }
            }
        }
    }
    return page;
}
}
