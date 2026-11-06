#include "android_host.hpp"
#include "../windows/project_game.hpp"
#include "../windows/raster_loader.hpp"
#include "../windows/chapter_card_art.hpp"
#include "../story_localization.hpp"
#include "../text_layer.hpp"
#include "../actor_panel.hpp"
#include "../mystery_panel_layer.hpp"
#include "../../core/choice_presentation.hpp"
#include "../../core/expandband_recomp.hpp"
#include "../../core/system_charts.hpp"
#include "../../core/name_entry.hpp"
#include "../../core/staff_roll.hpp"
#include <jni.h>
#include <android/bitmap.h>
#include <android/log.h>
#include <deque>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <cstring>

using namespace kx3;
using namespace kx3::platform;
using namespace kx3::platform::windows;
namespace {
using u32=std::uint32_t;
struct SystemString {u32 address;std::string_view bytes;const wchar_t *ja,*zh,*en;};
struct StaffLabel {std::string_view program;unsigned offset;std::string_view bytes;const wchar_t *zh,*en;};
#include "system_locale_data.inc"
std::unique_ptr<ProjectGame> game;
std::filesystem::path root;
std::string program="sn4g",error,feedback;
StoryLanguage language=StoryLanguage::chinese;
bool playing=false,audible=true,mounted=false;
std::deque<ChoiceInput> actions;
std::optional<ChoiceInput> failed_save_input;
std::vector<std::uint8_t> mark,love,actor_art;
ChapterCardArt card_art;
std::optional<unsigned> mystery_target;
// A touch level selects a destination, but only original 122328 pad edges move it.
std::optional<unsigned> interval_target;
bool interval_release=false;
bool interval_confirm=false;
struct CardClick {u32 state,key;bool release=false;};
std::optional<CardClick> card_click;
bool original_card=false;
bool card_open(){if(!game)return false;const auto& m=game->memory();const auto screen=m.read_u32(0x2388e8);return m.read_u32(0x2388cc)&&(screen==16||screen==5||((screen==12||screen==14)&&original_card));}
// Same input adapter as Win32 Player::chapter_pad: move the ORIGINAL focus
// with real pad edges, then confirm. Card dispatchers do not consume menu_index.
std::uint16_t card_pad(){
    if(!card_click)return 0;const auto& m=game->memory();auto& click=*card_click;
    if(!card_open()||m.read_u32(0x2380d0)!=click.state){card_click.reset();return 0;}
    if(click.release){click.release=false;return 0;}const auto key=click.key;
    if(key==0x300||key==0x301){if(m.read_u32(0x23815c))return 0;card_click.reset();return key==0x300?0x10:0x40;}
    std::uint16_t step=0;
    if(key<2&&m.read_u32(0x238058)!=key)step=0x10;
    if(key>=0x100&&key<0x102&&m.read_u32(0x2380a0)!=key-0x100)step=key==0x100?0x80:0x20;
    if(key>=0x200&&key<0x203){if(m.read_u32(0x23815c))return 0;const auto row=m.read_u32(0x238170);if(row!=key-0x200)step=row<key-0x200?0x40:0x10;}
    if(step){click.release=true;return step;}card_click.reset();return key==0x401?0x4000:0x2000;
}
std::string js(std::string_view s){std::ostringstream o;o<<'"';constexpr char h[]="0123456789abcdef";
    for(unsigned char c:s){if(c=='"'||c=='\\')o<<'\\'<<c;else if(c<32)o<<"\\u00"<<h[c>>4]<<h[c&15];else o<<c;}o<<'"';return o.str();}
std::string hex(std::string_view s){std::string r;constexpr char h[]="0123456789abcdef";for(unsigned char c:s){r+=h[c>>4];r+=h[c&15];}return r;}
std::string utf8(std::wstring_view s){std::string out;for(u32 c:s){if(c<0x80)out+=char(c);else if(c<0x800){out+=char(0xc0|(c>>6));out+=char(0x80|(c&63));}else if(c<0x10000){out+=char(0xe0|(c>>12));out+=char(0x80|((c>>6)&63));out+=char(0x80|(c&63));}else{out+=char(0xf0|(c>>18));out+=char(0x80|((c>>12)&63));out+=char(0x80|((c>>6)&63));out+=char(0x80|(c&63));}}return out;}
std::string ui(const char* zh,const char* en,const char* ja){return language==StoryLanguage::chinese?zh:language==StoryLanguage::english?en:ja;}
std::string system_text(u32 addr){for(auto& s:system_strings)if(s.address==addr)return utf8(language==StoryLanguage::chinese?s.zh:language==StoryLanguage::english?s.en:s.ja);return {};}
std::string base36(u32 v){std::string s;do{s+="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[v%36];v/=36;}while(v);std::reverse(s.begin(),s.end());return s;}
std::filesystem::path slot(std::string_view name,int i){return root/"saves"/(std::string(name)+"-"+std::to_string(i+1)+".kx3save");}
void bind_record(ProjectGame& g){g.set_system_record_file(root/"saves"/(program+"-system.dat"));}
void fail(const std::exception& e){error=e.what();actions.clear();mystery_target.reset();card_click.reset();if(game)game->suspend_audio_output();__android_log_print(ANDROID_LOG_ERROR,"MikazukiX3","%s",error.c_str());}
std::string location(){if(!game||!playing)return "10-1-0-0";const auto& m=game->memory();const auto system=system_menu_view(m,game->runtime().manager);
    const u32 s=m.read_u32(game->runtime().manager+0x38),base=m.read_u32(s+4),cursor=m.read_u32(s+0xd8);
    if(!base||cursor<base)return "10-1-0-0";
    std::string code=program=="sn2"?"11":program=="sn4"?"12":"13";
    code+='-'+base36(m.read_u32(s+0xd0))+'-'+base36(m.read_u32(s+0xd4))+'-'+base36(cursor-base);
    if(system.open)code+='-'+base36(system.screen)+'-'+base36(system.focus)+'-'+base36(system.subfocus);return code;
}
void blend(RasterFrame& dst,const RasterFrame& src){if(src.rgba.empty())return;if(src.width!=640||src.height!=448)throw std::runtime_error("Unexpected overlay size");
    for(std::size_t i=0;i<640u*448;++i){const auto* s=&src.rgba[4*i];auto* d=&dst.rgba[4*i];const unsigned a=s[3];if(!a)continue;
        const unsigned old=d[3]*(255-a),sum=a*255+old;for(unsigned c=0;c<3;++c)d[c]=std::uint8_t((s[c]*a*255+d[c]*old+sum/2)/sum);d[3]=(sum+127)/255;}}
void bitmap(JNIEnv* env,jobject image,const RasterFrame& frame){AndroidBitmapInfo info{};if(AndroidBitmap_getInfo(env,image,&info)||info.format!=ANDROID_BITMAP_FORMAT_RGBA_8888||info.width!=frame.width||info.height!=frame.height)throw std::runtime_error("Invalid Android bitmap");
    void* pixels=nullptr;if(AndroidBitmap_lockPixels(env,image,&pixels))throw std::runtime_error("Cannot lock Android bitmap");
    for(unsigned y=0;y<frame.height;++y){auto* d=static_cast<unsigned char*>(pixels)+y*info.stride;const auto* s=frame.rgba.data()+y*frame.width*4;
        for(unsigned x=0;x<frame.width;++x){for(unsigned c=0;c<3;++c)d[4*x+c]=s[4*x+c]*s[4*x+3]/255;d[4*x+3]=s[4*x+3];}}
    AndroidBitmap_unlockPixels(env,image);
}
jbyteArray bytes(JNIEnv* env,const std::string& s){auto a=env->NewByteArray(s.size());if(a)env->SetByteArrayRegion(a,0,s.size(),reinterpret_cast<const jbyte*>(s.data()));return a;}
std::string str(JNIEnv* env,jstring s){const char* p=env->GetStringUTFChars(s,nullptr);if(!p)throw std::runtime_error("Cannot read path");std::string r(p);env->ReleaseStringUTFChars(s,p);return r;}
void card_controls(std::ostringstream& o,const GuestMemory& m){
    const auto id=m.read_u32(0x238940),state=m.read_u32(0x2380d0);std::string hint;
    switch(id){
    case 14:hint=ui("选择用来保存进度的记忆卡。","Choose the memory card to save to.","");break;
    case 19:hint=ui("选择存档位置。","Choose a save slot.","");break;
    case 20:hint=ui("覆盖这个存档吗？","Overwrite this save?","");break;
    case 26:hint=ui("正在保存……","Saving…","");break;
    case 27:hint=ui("存档完成。","Save complete.","");break;
    case 28:hint=ui("存档失败。","Save failed.","");break;
    case 34:hint=ui("保存到目前为止的游戏进度吗？","Save your progress so far?","");break;
    case 35:hint=ui("进度不会保存。要继续吗？","Continue without saving your progress?","");break;
    case 36:hint=ui("确定结束游戏吗？","Are you sure you want to quit?","");break;
    case 39:hint=ui("游戏进度不会保存。仍要退出吗？","Your progress will not be saved. Quit anyway?","");break;
    }
    o<<",\"cardHint\":"<<js(hint)<<",\"cardControls\":[";bool comma=false;
    auto cell=[&](u32 key,std::string label,bool selected){if(comma)o<<',';comma=true;o<<"{\"id\":"<<(0x20000+key)<<",\"text\":"<<js(label)<<",\"selected\":"<<selected<<'}';};
    if(m.read_u32(0x23805c)){const auto focus=m.read_u32(0x238058);cell(1,ui("是","Yes","はい"),focus==1);cell(0,ui("否","No","いいえ"),focus==0);}
    else if(state==0x20 || (m.read_u32(0x2388e8)==12&&state==7)){
        for(u32 i=0;i<2;++i)cell(0x100+i,ui("接口 ","Port ","差込口 ")+std::to_string(i+1)+(m.read_u32(0x23a000+36*i)==2?ui(" · 未插卡"," · empty"," · 未挿入"):""),m.read_u32(0x2380a0)==i);
    }else if(m.read_u32(0x238150)&&!m.read_u32(0x23815c)&&(state==0x22||state==0x10)){
        for(u32 i=0;i<std::min(3u,m.read_u32(0x238184));++i){const auto p=m.read_u32(0x1e4bcf8+4*i);const bool used=m.read_u32(p+44);cell(0x200+i,(used?ui("存档 ","Save ","セーブ "):ui("新存档 ","New save ","新規 "))+std::to_string(1+(used?m.read_u32(p):m.read_u32(0x238168))),i==m.read_u32(0x238170));}
        if(m.read_u32(0x238184)>3){cell(0x300,ui("上一个","Previous","前へ"),false);cell(0x301,ui("下一个","Next","次へ"),false);}cell(0x401,ui("返回","Back","戻る"),false);
    }else if(state==0x25||state==0x18||state==0x29||state==0x2a||state==0x2b||(m.read_u32(0x2388e8)==12&&(state==0x15||state==0x16||state==0x17||state==0x1f||state==0x31)))cell(0x400,ui("确认","Confirm","決定"),true);
    o<<']';
}
std::string snapshot(){
    std::ostringstream o;o<<std::boolalpha;o<<"{\"mounted\":"<<mounted<<",\"playing\":"<<playing<<",\"program\":"<<js(program)<<",\"language\":"<<unsigned(language)<<",\"error\":"<<js(error)<<",\"message\":"<<js(feedback)<<",\"location\":"<<js(location());
    o<<",\"editions\":[";bool comma=false;
    if(game)for(const auto& e:source_title_selection(game->memory(),false).rows){if(comma)o<<',';comma=true;o<<js(e.program);}o<<"]";
    o<<",\"slots\":[";for(int i=0;i<10;++i){if(i)o<<',';o<<std::filesystem::is_regular_file(slot(program,i));}o<<"]";
    if(game&&playing){const auto& m=game->memory();const u32 manager=game->runtime().manager,script=m.read_u32(manager+0x38),font=m.read_u32(manager+0x3c);const auto menu=system_menu_view(m,manager);
        o<<",\"tick\":"<<game->logical_tick()<<",\"canMenu\":"<<system_menu_available(m,manager).value_or(false)<<",\"canBright\":"<<brightness_control_available(m,manager).value_or(false)<<",\"canInspect\":"<<inspection_control_available(m,manager).value_or(false)<<",\"audioError\":"<<js(game->audio_output_error());
        o<<",\"menu\":{\"open\":"<<menu.open<<",\"screen\":"<<menu.screen<<",\"focus\":"<<menu.focus<<",\"subfocus\":"<<menu.subfocus<<",\"settingsNotice\":"<<menu.settings_notice<<",\"canSave\":"<<menu.can_request_save<<",\"autoStop\":"<<menu.can_stop_auto<<",\"intervalReady\":"<<menu.interval_ready<<",\"interval\":"<<menu.interval_level<<",\"notice\":"<<js(system_text(menu.notice_text_address))<<",\"brightness\":"<<menu.brightness_level<<",\"brightOpen\":"<<menu.brightness_visible<<",\"actions\":[";
        for(unsigned i=0;i<menu.actions.size();++i){if(i)o<<',';o<<unsigned(menu.actions[i]);}o<<"],\"settings\":[";
        for(unsigned i=0;i<4;++i){if(i)o<<',';o<<menu.settings[i];}o<<"],\"originalCard\":"<<original_card<<'}';
        o<<",\"lines\":[";comma=false;
        if(!m.read_u32(font+0x28))for(const auto& line:localize_story_page(m,script,language,game->visible_text_events(),program).lines){if(comma)o<<',';comma=true;
            o<<"{\"text\":"<<js(line.player_name_cp932?"":line.text)<<",\"raw\":"<<js(line.player_name_cp932?hex(line.text):"")<<",\"x\":"<<line.x<<",\"y\":"<<line.y<<",\"height\":"<<line.height<<",\"alpha\":"<<line.opacity<<",\"color\":"<<line.rgb<<",\"option\":"<<line.option<<",\"name\":"<<line.player_name_cp932<<'}';}o<<"]";
        auto name=name_entry_view(m,manager);o<<",\"name\":{\"open\":"<<name.open<<",\"confirming\":"<<name.confirming<<",\"slot\":"<<name.slot<<",\"focus\":"<<name.focus<<",\"confirmFocus\":"<<name.confirm_focus<<",\"draft\":"<<js(hex(name.draft_cp932))<<",\"cells\":[";comma=false;
        for(const auto& cell:name.cells){if(comma)o<<',';comma=true;o<<"{\"id\":"<<cell.index<<",\"col\":"<<cell.column<<",\"row\":"<<cell.row<<",\"raw\":"<<js(hex(cell.text_cp932))<<'}';}o<<"]}";
        const auto actor=game->actor_choice();o<<",\"actors\":"<<actor.open<<",\"actorFocus\":"<<actor.focus<<",\"mystery\":"<<mystery::active(m);
        const bool card=card_open();o<<",\"card\":"<<card<<",\"cardMessage\":"<<m.read_u32(0x238940)<<",\"cardState\":"<<m.read_u32(0x2380d0)<<",\"yesNo\":"<<(m.read_u32(0x23805c)!=0)<<",\"yesFocus\":"<<m.read_u32(0x238058);
        if(card)card_controls(o,m);
        if(menu.open&&menu.screen==1){const auto chart=visible_time_chart(m);o<<",\"chartFirst\":"<<chart.first_row<<",\"chartFocus\":"<<(chart.row*4+chart.actor);}
        o<<",\"items\":[";comma=false;auto item=[&](u32 id,const std::string& text,bool enabled){if(comma)o<<',';comma=true;o<<"{\"id\":"<<id<<",\"text\":"<<js(text)<<",\"enabled\":"<<enabled<<'}';};
        if(menu.open&&menu.screen==3){auto entries=ending_list_entries(m);for(u32 i=0;i<entries.size();++i)item(i,entries[i].replay_prompt?system_text(0x229738):entries[i].reached?std::string(localize_chart_title(program+"-end",i,entries[i].title_cp932,language)):"",entries[i].reached||entries[i].replay_prompt);}
        if(menu.open&&menu.screen==2){auto list=visible_chapter_list(m);for(u32 i=list.first;i<list.rows.size()&&i<list.first+8;++i){const auto& row=list.rows[i];item(i,std::to_string(row.number)+"  "+std::string(localize_chart_title(program+"-chap",row.source_id,row.title_cp932,language)),true);}}
        if(menu.open&&menu.screen==1){auto chart=visible_time_chart(m);for(const auto& cell:chart.available_cells)if(cell.time_row>=chart.first_row&&cell.time_row<chart.first_row+12)item(cell.time_row*4+cell.actor,std::string(localize_chart_title("sn4g-time",cell.title_id,cell.title_cp932,language)),true);}
        o<<"],\"credits\":[";comma=false;for(const auto& line:credits::visible_lines(m)){if(comma)o<<',';comma=true;std::string text;
            if(language!=StoryLanguage::japanese)for(const auto& r:staff_labels)if(r.program==program&&r.offset==line.offset&&r.bytes==line.original){text=utf8(language==StoryLanguage::chinese?r.zh:r.en);break;}
            o<<"{\"text\":"<<js(text)<<",\"raw\":"<<js(text.empty()?hex(line.original):"")<<",\"x\":"<<line.x<<",\"y\":"<<line.y<<",\"size\":"<<line.size<<",\"align\":"<<line.alignment<<",\"anchor\":"<<line.anchor<<'}';}o<<"]";
    }o<<'}';return o.str();
}
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_open(JNIEnv* env,jclass,jint fd,jstring path){try{
    game.reset();mounted=false;playing=false;actions.clear();android::mount_disc_fd(fd);mounted=true;root=str(env,path);std::filesystem::create_directories(root/"saves");
    program="sn4g";game=std::make_unique<ProjectGame>(root,program);bind_record(*game);
    mark=read_disc_resource(root,"EFFECT/mark.ctf","1640696c4886e47890bd25651c6f1075ca9cf4c2a05a689e2fc373974ae296fb",8384);
    love=read_disc_resource(root,"EFFECT/love.ctf","b0b84740ca2a246b2c50d94851c850a4b568a068a0e7faadaf16063716e0c952",8384);error.clear();feedback.clear();
    }catch(const std::exception& e){fail(e);}return bytes(env,snapshot());}
extern "C" JNIEXPORT void JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_start(JNIEnv* env,jclass,jstring edition,jint save){try{
    auto nextProgram=str(env,edition);if(nextProgram!="sn2"&&nextProgram!="sn4"&&nextProgram!="sn4g")throw std::runtime_error("Invalid original edition");
    const bool note=save>=100&&save<110;if((save<-2||save>=10)&&!note)throw std::runtime_error("Invalid save slot");
    auto next=note?ProjectGame::load_note(root,nextProgram,root/"saves"/(nextProgram+"-system.dat"),save-100):save==-1?std::make_unique<ProjectGame>(root,nextProgram):ProjectGame::load(root,nextProgram,save==-2?root/"saves"/(nextProgram+"-suspend.kx3save"):slot(nextProgram,save));
    failed_save_input.reset();card_click.reset();original_card=false;game=std::move(next);program=nextProgram;if(!note)bind_record(*game);playing=true;error.clear();feedback.clear();actions.clear();mystery_target.reset();if(audible)game->enable_audio_output();
    }catch(const std::exception& e){fail(e);}}
extern "C" JNIEXPORT jintArray JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_notes(JNIEnv* env,jclass,jstring edition){
    std::vector<jint> result;try{const auto name=str(env,edition);if(name!="sn2"&&name!="sn4"&&name!="sn4g")throw std::runtime_error("Invalid note edition");const auto slots=ProjectGame::note_slots(root,name,root/"saves"/(name+"-system.dat"));result.assign(slots.begin(),slots.end());}
    catch(const std::exception& e){feedback=e.what();__android_log_print(ANDROID_LOG_WARN,"MikazukiX3","Read original card: %s",e.what());}
    auto out=env->NewIntArray(result.size());if(out&&!result.empty())env->SetIntArrayRegion(out,0,result.size(),result.data());return out;
}
extern "C" JNIEXPORT void JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_action(JNIEnv*,jclass,jint kind,jint index){try{
    if(!game||!playing||!error.empty())return;ChoiceInput in;
    if(kind==0){
        // A fast second tap must confirm the requested level, not an intermediate
        // source focus. Keep driving original pad edges until the target is ready.
        if(index==0x2000&&interval_target){const auto menu=system_menu_view(game->memory(),game->runtime().manager);if(menu.open&&menu.screen==10){interval_confirm=true;return;}}
        in.held=std::uint16_t(index);
    }
    else if(kind==1){in.mouse_index=index;in.mouse_confirm=true;}
    else if(kind==2){if(index>=0x20000&&card_open()){card_click=CardClick{game->memory().read_u32(0x2380d0),u32(index-0x20000)};return;}in.menu_index=index;in.menu_confirm=true;}
    else if(kind==3){in.name_index=index;in.name_confirm=true;}
    else if(kind==4){in.actor_index=index;in.actor_confirm=true;}
    else if(kind==5){
        if(name_entry_view(game->memory(),game->runtime().manager).open || system_menu_view(game->memory(),game->runtime().manager).open || game->actor_choice().open)return;
        const int x=index&65535,y=(unsigned(index)>>16)&65535;auto option=source_choice_at(game->memory(),game->runtime().manager,x,y);
        if(option){in.mouse_index=*option;in.mouse_confirm=true;}else if(mystery::active(game->memory())){int selected=mystery::option_at(game->memory(),x,y);if(selected>=0)mystery_target=unsigned(selected);return;}else in.held=0x2000;}
    else if(kind==6){const auto menu=system_menu_view(game->memory(),game->runtime().manager);if(menu.open&&(menu.screen==12||menu.screen==14)){original_card=true;actions.clear();}return;}
    else if(kind==7){const auto menu=system_menu_view(game->memory(),game->runtime().manager);if(menu.open&&menu.screen==10&&menu.interval_ready&&index>=1&&index<=5){interval_target=unsigned(index);interval_release=false;interval_confirm=false;}return;}
    else return;
    interval_target.reset();
    if(actions.size()<8){actions.push_back(in);actions.push_back({});}
}catch(const std::exception& e){fail(e);}}
extern "C" JNIEXPORT void JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_tick(JNIEnv*,jclass,jint held){if(!game||!playing||!error.empty())return;ChoiceInput input;try{
    if(!actions.empty()){input=actions.front();actions.pop_front();}input.held|=std::uint16_t(held);
    const auto& m=game->memory();const auto screen=m.read_u32(0x2388e8);
    if(original_card&&(!m.read_u32(0x2388cc)||(screen!=14&&screen!=12)))original_card=false;
    input.original_card_menu=original_card;if(input.held)card_click.reset();else input.held=card_pad();
    if(interval_target){const auto menu=system_menu_view(m,game->runtime().manager);
        if(input.held||!menu.open||menu.screen!=10)interval_target.reset();
        else if(menu.interval_level==*interval_target){if(menu.interval_ready){interval_target.reset();if(interval_confirm)input.held=0x2000;interval_confirm=false;}}
        else if(interval_release)interval_release=false;
        else if(menu.interval_ready){input.held=menu.interval_level<*interval_target?0x20:0x80;interval_release=true;}}
    if(mystery_target){const auto& m=game->memory();const int current=mystery::selected(m);if(input.held||current<0)mystery_target.reset();
        else if(!m.read_u16(0x238700)){if(current!=int(*mystery_target))input.held=0x8000;else{input.held=0x2000;mystery_target.reset();}}}
    game->advance(input);
    if(game->memory().read_u32(0x238680)){playing=false;game->suspend_audio_output();actions.clear();}
     }catch(const CardWriteError& e){failed_save_input=input;fail(e);}
      catch(const std::system_error& e){if(game->memory().read_u32(0x239fe8)&&game->memory().read_u32(0x239fa4)==1)failed_save_input=input;fail(e);}
      catch(const std::exception& e){fail(e);}}
extern "C" JNIEXPORT jbyteArray JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_state(JNIEnv* env,jclass){try{return bytes(env,snapshot());}catch(const std::exception& e){fail(e);return bytes(env,"{\"error\":"+js(error)+"}");}}
extern "C" JNIEXPORT void JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_language(JNIEnv*,jclass,jint lang){if(lang>=0&&lang<=2)language=StoryLanguage(lang);}
extern "C" JNIEXPORT void JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_pause(JNIEnv*,jclass,jboolean paused,jboolean checkpoint){audible=!paused;actions.clear();card_click.reset();interval_target.reset();if(!game)return;
    if(paused){game->suspend_audio_output();if(checkpoint&&playing&&error.empty())try{game->save(root/"saves"/(program+"-suspend.kx3save"));}catch(const std::exception& e){feedback=std::string("Background checkpoint: ")+e.what();}}
    else if(playing&&error.empty())game->enable_audio_output();}
extern "C" JNIEXPORT void JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_save(JNIEnv*,jclass,jint index){try{
    if(!game||!playing||index<0||index>=10)throw std::runtime_error("Invalid save request");const auto menu=system_menu_view(game->memory(),game->runtime().manager);
    if(!menu.open)throw std::runtime_error("Save from the original game menu");
    if(menu.screen==12)game->save_auto_target(slot(program,index),index);
    else if(menu.screen==14&&menu.can_request_save){game->save_from_menu(slot(program,index));playing=false;game->suspend_audio_output();}
    else throw std::runtime_error("Original game does not allow saving here");feedback=ui("进度已保存。","Progress saved.","セーブしました。");error.clear();actions.clear();
    }catch(const std::exception& e){feedback=e.what();}}
extern "C" JNIEXPORT void JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_home(JNIEnv*,jclass){if(game)game->suspend_audio_output();playing=false;actions.clear();}
extern "C" JNIEXPORT void JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_retry(JNIEnv*,jclass){error.clear();if(failed_save_input){actions.push_front(*failed_save_input);failed_save_input.reset();}if(game&&audible)game->enable_audio_output();}
extern "C" JNIEXPORT void JNICALL Java_org_wwesun2000_mikazukix3_NativeBridge_render(JNIEnv* env,jclass,jobject scene,jobject layer,jobject foreground,jboolean scan){if(!game||!playing)return;try{
    const auto& m=game->memory();RasterFrame frame{640,448,std::vector<std::uint8_t>(640*448*4)};
    if(auto src=game->scene_frame()){if(src->width!=640||src->height!=448)throw std::runtime_error("Unexpected scene size");frame=*src;}
    const auto shade=original_background_darkening(m).value_or(0);
    for(unsigned y=0;y<448;++y)for(unsigned x=0;x<640;++x){auto* p=&frame.rgba[4*(y*640+x)];for(unsigned c=0;c<3;++c){p[c]=p[c]*(128-shade)/128;if(scan&&(y&1))p[c]=p[c]*195/255;}p[3]=255;}
    bitmap(env,scene,frame);
    RasterFrame over{640,448,std::vector<std::uint8_t>(640*448*4)};const auto font=m.read_u32(game->runtime().manager+0x3c);
    const std::array<TextAtlasResource,2> atlases={TextAtlasResource{0,mark},TextAtlasResource{4,love}};
    blend(over,render_text_layer(m,font,atlases,language==StoryLanguage::japanese?TextLayerParts::all:TextLayerParts::artwork));bitmap(env,layer,over);
    std::fill(over.rgba.begin(),over.rgba.end(),0);if(auto fg=game->foreground_frame())blend(over,*fg);
    const auto actor=game->actor_choice();if(actor.open){if(actor_art.empty())actor_art=read_disc_resource(root,"PANEL/hrsel.dat","c082f7c5efeb512abf48fca6813f691c04c1448748a5c185c32d2caad13a5108",2926592);blend(over,render_actor_panel(actor,actor_art));}
    blend(over,render_mystery_panel(m));const auto menu=system_menu_view(m,game->runtime().manager);
    if(card_open())blend(over,card_art.message(root,m,m.read_u32(0x238940)));
    bitmap(env,foreground,over);
    }catch(const std::exception& e){fail(e);}}
