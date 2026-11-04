#define NOMINMAX
#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <shellapi.h>
#include <uxtheme.h>
#include "project_game.hpp"
#include "../../core/staff_roll.hpp"
#include "../../core/retail_disc.hpp"
#include "../../core/save.hpp"
#include "raster_loader.hpp"
#include "window_drawing.hpp"
#include "scene_surface.hpp"
#include "story_text_layout.hpp"
#include "../field_sprite.hpp"
#include "chapter_card_art.hpp"
#include "../text_layer.hpp"
#include "../story_localization.hpp"
#include "../scale2x.hpp"
#include "../actor_panel.hpp"
#include "../mystery_panel_layer.hpp"
#include "../../core/choice_presentation.hpp"
#include "../../core/manager_input.hpp"
#include "../../core/system_menu.hpp"
#include "../../core/system_charts.hpp"
#include "../../core/name_entry.hpp"
#include "../../core/title_selection.hpp"
#include "../../core/particle_effect.hpp"
#include "../../core/expandband_recomp.hpp"
#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstdlib>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <memory>
#include <set>
#include <sstream>

namespace kx3::platform::windows {
namespace {
using u32=std::uint32_t;
using Clock=std::chrono::steady_clock;
constexpr auto cycle=std::chrono::nanoseconds(16'666'667);
constexpr COLORREF rail_color=RGB(13,20,32),brass=RGB(225,187,138),ivory=RGB(236,231,219),slate=RGB(138,150,165);
constexpr UINT verify_msg=WM_APP+21;
constexpr UINT title_pad_msg=WM_APP+22;
constexpr UINT overwrite_timer=831;
constexpr unsigned continue_slot_message=500;
constexpr unsigned pc_slots=10; // Original 105538/1057B8 slot domain.
constexpr unsigned slots_per_page=5;
constexpr wchar_t title[]=L"镰鼬之夜 ×3";
struct SystemString {
    std::uint32_t address;
    std::string_view bytes;
    const wchar_t *ja,*zh,*en;
};
struct StaffLabel {std::string_view program; unsigned offset; std::string_view bytes; const wchar_t *zh,*en;};
#include "system_locale_data.inc"

void require(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
std::wstring wide(std::string_view s,UINT encoding=CP_UTF8) {
    if(s.empty())return {};
    int n=MultiByteToWideChar(encoding,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
    require(n>0,"Invalid encoded source text");
    std::wstring out(n,L' ');
    MultiByteToWideChar(encoding,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n);
    return out;
}
std::wstring frontier_address(std::string_view reason){
    for(std::size_t i=0;i<reason.size();){
        if(!std::isxdigit(static_cast<unsigned char>(reason[i]))){++i;continue;}
        const auto start=i;
        while(i<reason.size() && std::isxdigit(static_cast<unsigned char>(reason[i])))++i;
        if(i-start>=6 && i-start<=8)return L"0x"+wide(reason.substr(start,i-start));
    }
    return {};
}
void fill(HDC dc,RECT r,COLORREF c){
    HBRUSH brush=CreateSolidBrush(c);FillRect(dc,&r,brush);DeleteObject(brush);
}
void line(HDC dc,int x,int y,int x2,int y2){MoveToEx(dc,x,y,nullptr);LineTo(dc,x2,y2);}
// Coordinate space is the original 640x448 text surface displayed at 4:3.
struct Layout { RECT rail,screen,settings; };
enum class RailCommand { open, display, resume, source, save_slot, slot_page, original_card, retry_save, back, interval_pad, brightness_pad, inspect_hold, unavailable };
enum class Lobby { hidden,home,new_game,load_game,slots,new_note };
struct RailRow { RailCommand command;unsigned value;std::wstring label;bool enabled,selected;RECT rect; };
std::string utf8(std::wstring_view w){
    const int n=WideCharToMultiByte(CP_UTF8,0,w.data(),int(w.size()),nullptr,0,nullptr,nullptr);
    std::string s(n,' ');WideCharToMultiByte(CP_UTF8,0,w.data(),int(w.size()),s.data(),n,nullptr,nullptr);return s;
}
std::wstring base36(u32 value){
    constexpr wchar_t digits[]=L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::wstring text;
    do{text.push_back(digits[value%36]);value/=36;}while(value);
    std::reverse(text.begin(),text.end());return text;
}
Layout layout(int w,int h){
    w=std::max(1,w);h=std::max(1,h);
    const int rail=w>=4*h/3+128 ? std::min(w-4*h/3,std::clamp(h/3,230,460)) : 0;
    const int sw=std::min(w-rail,4*h/3),sh=sw==4*h/3?h:std::max(1,(3*sw+2)/4),left=rail+(w-rail-sw)/2;
    return {{0,0,rail,h},{left,0,left+sw,sh},{0,h*57/100,rail,h*57/100+42}};
}
std::uint16_t physical_key(unsigned key){
    switch(key){
    case VK_UP:return 0x10;case VK_RIGHT:return 0x20;case VK_DOWN:return 0x40;case VK_LEFT:return 0x80;
    case VK_RETURN:case VK_SPACE:case 'L':return 0x2000;
    case 'T':return 0x0008;
    case VK_BACK:case 'K':return 0x4000;case 'I':return 0x1000;case 'J':return 0x8000;
    case VK_PRIOR:return 0x400;case VK_NEXT:return 0x800;case VK_HOME:return 0x100;case VK_END:return 0x200;
    default:return 0;
    }
}
struct Player {
    std::filesystem::path root;
    std::string program;
    Lobby lobby=Lobby::hidden;
    TitleSelection editions;
    std::map<std::string,std::vector<unsigned>> notes;
    unsigned lobby_focus=0,load_edition=0;
    std::optional<unsigned> lobby_press;
    std::vector<RECT> lobby_buttons;
    std::unique_ptr<ProjectGame> game;
    std::vector<std::uint8_t> mark,love;
    std::vector<std::uint8_t> actor_art;
    ActorChoiceView actors{};
    RasterFrame actor_overlay;
    RasterFrame mystery_overlay;
    std::optional<int> mystery_press,mystery_target;
    unsigned mystery_source=0;
    std::optional<unsigned> actor_hover,actor_press;
    bool actor_click=false;
    HWND window=nullptr;
    HFONT title_font=create_ui_font(25,FW_NORMAL,L"SimSun"),body=create_ui_font(16,FW_NORMAL),small=create_ui_font(13,FW_NORMAL);
    HFONT menu_font=nullptr,locator_font=nullptr;
    int menu_height=0;
    bool fullscreen=false,smooth=true,scans=false,scale2x=false,settings_open=false,verify=false,failed=false;
    bool display_page=false,display_inspection=false,display_about=false;
    LONG about_scroll=0,about_scroll_max=0;
    unsigned display_focus=0;
    std::optional<unsigned> display_press;
    std::vector<RECT> display_buttons;
    std::array<bool,256> display_key_release{};
    bool pressed_stage=false,had_prepared_only=false;
    std::optional<u32> pressed_choice,pending_choice;
    bool choice_confirm=false;
    std::array<bool,256> keys{};
    bool mouse_inspection=false;
    std::uint16_t pressed=0;
    WINDOWPLACEMENT placement{sizeof(WINDOWPLACEMENT)};
    LONG_PTR style=0;
    std::string frontier;
    std::optional<ChoiceInput> failed_save_input;
    std::wstring displayed_caption;
    Clock::time_point next=Clock::now()+cycle;
    std::uint64_t frames=0,steps=0;
    // Opt-in measurement of application paint submissions and their CPU stages.
    // Buffer in memory so filesystem writes cannot stall measured frames.
    const wchar_t* trace_path=_wgetenv(L"KX3_FRAME_TRACE");
    struct Timing {std::int64_t us;std::uint64_t tick,generation;unsigned picture;const char* event;std::int64_t audio_us;};
    std::vector<Timing> timings;
    void timing(const char* event){
        if(!trace_path || timings.size()>=120000)return;
        if(timings.empty())timings.reserve(120000);
        const auto us=std::chrono::duration_cast<std::chrono::microseconds>(Clock::now().time_since_epoch()).count();
        timings.push_back({us,game->logical_tick(),game->images().current_generation(),game->images().visible_frame(),event,game->output_submit_us()});
    }
    void finish_timings()const{
        if(!trace_path)return;
        std::ofstream out{std::filesystem::path(trace_path)};
        out.exceptions(std::ios::badbit|std::ios::failbit);
        out<<"steady_us,tick,generation,picture,event,audio_submit_us\n";
        for(const auto& s:timings)out<<s.us<<','<<s.tick<<','<<s.generation<<','<<s.picture<<','<<s.event<<','<<s.audio_us<<'\n';
    }
    u32 glyph_count=0;
    std::shared_ptr<const RasterFrame> scene;
    unsigned scene_darkening=0;
    std::vector<u32> scene_pixels;
    RasterFrame letters,marks;
    StoryLanguage language=StoryLanguage::chinese;
    StoryLanguage initial_language=StoryLanguage::chinese;
    LocalizedPage translated;
    std::vector<TranslatedOptionHit> translated_options;
    struct StoryCache {
        HDC dc=nullptr;
        HBITMAP bitmap=nullptr;
        HGDIOBJ original=nullptr;
        RECT bounds{};
        std::uint64_t image=0;
        bool valid=false,filtered=false,visible=false;
        std::vector<LocalizedLine> lines;
        void reset(){
            if(original)SelectObject(dc,original);
            if(bitmap)DeleteObject(bitmap);
            if(dc)DeleteDC(dc);
            dc=nullptr;bitmap=nullptr;original=nullptr;valid=false;
        }
        ~StoryCache(){reset();}
        bool capture(HDC source,RECT rect){
            const int w=rect.right-rect.left,h=rect.bottom-rect.top;
            if(w<=0 || h<=0)return false;
            if(!dc || !EqualRect(&rect,&bounds)){
                reset();bounds=rect;dc=CreateCompatibleDC(source);
                if(!dc)return false;
                bitmap=CreateCompatibleBitmap(source,w,h);
                if(!bitmap){reset();return false;}
                original=SelectObject(dc,bitmap);
                if(!original){reset();return false;}
            }
            return BitBlt(dc,0,0,w,h,source,rect.left,rect.top,SRCCOPY)!=0;
        }
    } story_cache;
    std::uint64_t image_revision=0;
    std::set<std::string> missing;
    std::filesystem::path preferences,missing_file;
    unsigned original_text_paints=0,translated_text_paints=0;
    std::optional<unsigned> menu_hover,rail_press;
    std::optional<unsigned> chart_press;
    std::optional<unsigned> name_hover,name_press;
    bool name_click=false;
    std::vector<std::pair<RECT,unsigned>> chart_cells;
    std::vector<std::pair<RECT,unsigned>> name_cells;
    bool menu_click=false;
    unsigned selected_slot=0;
    ProjectMixer title_mixer;
    std::unique_ptr<WaveOutput> title_output;
    std::uint16_t title_edges=0;
    bool use_original_card=false;
    ChapterCardArt chapter_art;
    RasterFrame chapter_message;
    u32 chapter_message_id=UINT32_MAX;
    struct CardClick {u32 state,key;bool release=false;};
    std::optional<CardClick> chapter_click;
    unsigned slot_writes=0;
    bool last_system_request=false;
    unsigned modal_reply=0,modal_clicked=0;
    bool menu_test=false;
    unsigned prefs_test=0;
    unsigned extra_test=0;
    bool has_progress=false;
    std::wstring feedback;
    std::filesystem::path screenshot;
    std::filesystem::path chapter_test_folder;

    Player(std::filesystem::path project,bool checking,StoryLanguage initial,bool check_menu,unsigned check_prefs,unsigned extra):root(std::move(project)),program(extra==12 || extra==13 || extra==14 || (extra>=16 && extra<=18)?"sn4":(extra>=1 && extra<=3) || extra==7 || extra==8 || extra==9 || extra==11 || extra==32 || extra==41?"sn2":"sn4g"),game(std::make_unique<ProjectGame>(root,program)),verify(checking),language(initial),initial_language(initial),menu_test(check_menu),prefs_test(check_prefs),extra_test(extra) {
        if(extra==15 || (extra>=35 && extra<=39) || extra==41)chapter_test_folder=root/"local/diagnostics/card-batch"/
            ("window-"+std::to_string(GetCurrentProcessId())+"-"+std::to_string(GetTickCount64()));
        game->set_system_record_file(slot_path(0).parent_path()/(program+"-system.dat"));
        mark=read_disc_resource(root,"EFFECT/mark.ctf",
            "1640696c4886e47890bd25651c6f1075ca9cf4c2a05a689e2fc373974ae296fb",8384);
        love=read_disc_resource(root,"EFFECT/love.ctf",
            "b0b84740ca2a246b2c50d94851c850a4b568a068a0e7faadaf16063716e0c952",8384);
        preferences=root/"local/pc-core/player"/(prefs_test?"verification-display.ini":"display.ini");
        missing_file=root/"local/pc-core/player/translation-missing.txt";
        if(!verify || prefs_test){
            const auto saved=GetPrivateProfileIntW(L"display",L"language",1,preferences.c_str());
            if(saved<=2)language=static_cast<StoryLanguage>(saved);
            smooth=GetPrivateProfileIntW(L"display",L"smooth",1,preferences.c_str())!=0;
            scans=GetPrivateProfileIntW(L"display",L"scanlines",0,preferences.c_str())!=0;
            scale2x=GetPrivateProfileIntW(L"display",L"scale2x",0,preferences.c_str())!=0;
        }
        if(!verify){
            std::ifstream existing(missing_file);std::string line;
            while(std::getline(existing,line))missing.insert(line);
            game->enable_audio_output();
        }
        for(unsigned i=0;i<pc_slots;++i)has_progress|=std::filesystem::is_regular_file(slot_path(i));
        if(!verify || extra_test==5)open_title();
    }
    ~Player(){for(auto font:{title_font,body,small,menu_font,locator_font})if(font)DeleteObject(font);}
    std::filesystem::path report_path()const{
        if(extra_test==31)return root/"analysis/native-core/player-controls.json";
        if(extra_test==32)return root/"analysis/native-core/player-autosave-ten.json";
        if(extra_test==33)return root/"analysis/native-core/player-autosave-retry.json";
        if(extra_test==34)return root/"analysis/native-core/player-brightness.json";
        if(extra_test==35)return root/"analysis/native-core/player-chapter-card-retry.json";
        if(extra_test==36)return root/"analysis/native-core/player-new-note.json";
        if(extra_test==37)return root/"analysis/native-core/player-system-card.json";
        if(extra_test==38)return root/"analysis/native-core/player-system-card-write.json";
        if(extra_test==39)return root/"analysis/native-core/player-system-card-bound.json";
        if(extra_test==40)return root/"analysis/native-core/player-wind.json";
        if(extra_test==41)return root/"analysis/native-core/player-system-card-auto.json";
        if(extra_test==42)return root/"analysis/native-core/player-wipes.json";
        if(extra_test==43)return root/"analysis/native-core/player-letter-blur.json";
        if(extra_test==44)return root/"analysis/native-core/player-mesh.json";
        if(extra_test==30)return root/"analysis/native-core/player-interval.json";
        if(extra_test==15)return root/"analysis/native-core/player-chapter-card.json";
        if(extra_test==16)return root/"analysis/native-core/player-credits.json";
        if(extra_test==17)return root/"analysis/native-core/player-culprit.json";
        if(extra_test==18)return root/"analysis/native-core/player-memory-panel.json";
        if(extra_test==19)return root/"analysis/native-core/player-reordered-clue.json";
        if(extra_test==20)return root/"analysis/native-core/player-simultaneous.json";
        if(extra_test==21)return root/"analysis/native-core/player-answer-keyboard.json";
        if(extra_test==22)return root/"analysis/native-core/player-english-waits.json";
        if(extra_test==23)return root/"analysis/native-core/player-incoming-slide.json";
        if(extra_test==24)return root/"analysis/native-core/player-zoom.json";
        if(extra_test==25)return root/"analysis/native-core/player-shake.json";
        if(extra_test==26)return root/"analysis/native-core/player-feedback.json";
        if(extra_test==27)return root/"analysis/native-core/player-eight-options.json";
        if(extra_test==28)return root/"analysis/native-core/player-ending-eight.json";
        if(extra_test==29)return root/"analysis/native-core/player-alternate-ending.json";
        if(extra_test==14)return root/"analysis/native-core/player-poem.json";
        if(extra_test==4)return root/"analysis/native-core/player-charts.json";
        if(extra_test==5)return root/"analysis/native-core/player-title.json";
        if(extra_test==6)return root/"analysis/native-core/player-snow.json";
        if(extra_test==9)return root/"analysis/native-core/player-autosave.json";
        if(extra_test==10)return root/"analysis/native-core/player-actors.json";
        if(extra_test==13)return root/"analysis/native-core/player-colors.json";
        if(extra_test==11 || extra_test==12)return root/"analysis/native-core"/("player-chapters-"+program+".json");
        if(extra_test==7 || extra_test==8)return root/"analysis/native-core"/(extra_test==7?"player-choice-a-mouse.json":"player-choice-b-key.json");
        if(extra_test)return root/"analysis/native-core"/(extra_test==1?"player-choice-a.json":extra_test==2?"player-choice-b.json":"player-name.json");
        if(prefs_test)return root/"analysis/native-core"/(prefs_test==1?"player-window-prefs-write.json":"player-window-prefs-read.json");
        return root/"analysis/native-core"/(menu_test?"player-menu-window.json":initial_language==StoryLanguage::english?"player-window-en.json":"player-window.json");
    }
    std::filesystem::path capture(std::string_view name)const{
        return capture_window_client(window,root/"local/pc-core/player/qa-captures"/name,false);
    }
    std::wstring title_location()const{
        return L"10-"+base36(unsigned(lobby))+L"-"+base36(lobby_focus)+L"-"+
               base36(lobby==Lobby::slots || lobby==Lobby::new_note?load_edition:0);
    }
    std::filesystem::path capture_screenshot(){
        std::filesystem::path saved;
        try{
            auto code=lobby==Lobby::hidden?location_code(menu()):title_location();
            if(code.empty())code=L"scene-"+std::to_wstring(game->logical_tick());
            const wchar_t* locales[]={L"ja",L"zh-Hans",L"en"};
            const auto dir=verify?root/"local/pc-core/player/qa-captures/manual":root/"captures/screenshots";
            const auto file=code+L"-"+locales[unsigned(language)]+(scale2x?L"-2x":smooth?L"-smooth":L"-nearest")+(scans?L"-scan.png":L".png");
            feedback.clear();
            saved=capture_window_client(window,dir/file,true);
            feedback=ui(L"截图已保存 · captures/screenshots",L"Saved to captures/screenshots",L"captures/screenshots に保存しました");
        }catch(const std::exception& e){
            feedback=std::wstring(ui(L"截图失败 · ",L"Screenshot failed · ",L"画像保存失敗 · "))+wide(e.what());
        }
        InvalidateRect(window,nullptr,FALSE);
        return saved;
    }
    Layout view()const {
        RECT r{};GetClientRect(window,&r);auto result=layout(r.right,r.bottom);
        const auto state=menu();
        if(!result.rail.right && (state.open || state.controls_visible)){
            const int rail=std::clamp(int(r.right)/3,100,160),w=std::max(1,int(r.right)-rail);
            result.rail={0,0,rail,r.bottom};result.screen={rail,0,rail+w,std::min(r.bottom,LONG(w*3/4))};
        }
        return result;
    }
    void clear_keys(){title_edges=0;mouse_inspection=false;keys.fill(false);pressed=0;pending_choice.reset();choice_confirm=false;pressed_stage=false;pressed_choice.reset();rail_press.reset();chart_press.reset();menu_hover.reset();menu_click=false;name_hover.reset();name_press.reset();name_click=false;actor_hover.reset();actor_press.reset();actor_click=false;mystery_press.reset();mystery_target.reset();chapter_click.reset();}
    const wchar_t* ui(const wchar_t* zh,const wchar_t* en,const wchar_t* ja)const{
        return language==StoryLanguage::english?en:language==StoryLanguage::japanese?ja:zh;
    }
    const wchar_t* caption()const{return ui(title,L"Kamaitachi no Yoru ×3",L"かまいたちの夜 ×3");}
    void refresh_caption(){
        const auto value=frontier.empty()?std::wstring(caption()):std::wstring(caption())+L" · "+wide(frontier);
        if(value!=displayed_caption && SetWindowTextW(window,value.c_str()))displayed_caption=value;
    }
    SystemMenuView menu()const{return system_menu_view(game->memory(),game->runtime().manager);}
    bool chapter_open()const{return game->memory().read_u32(0x2388cc) && game->memory().read_u32(0x2388e8)==16;}
    bool card_controls_open()const{
        const auto& m=game->memory();
        const auto screen=m.read_u32(0x2388e8);
        return m.read_u32(0x2388cc) && (screen==16 || screen==5 || ((screen==12 || screen==14) && use_original_card));
    }
    std::uint16_t chapter_pad(){
        if(!chapter_click)return 0;
        const auto& m=game->memory();
        auto& click=*chapter_click;
        if(!card_controls_open() || m.read_u32(0x2380d0)!=click.state){chapter_click.reset();return 0;}
        if(click.release){click.release=false;return 0;}
        const auto key=click.key;
        if(key==0x300 || key==0x301){
            if(m.read_u32(0x23815c))return 0;
            chapter_click.reset();return key==0x300?0x10:0x40;
        }
        std::uint16_t step=0;
        if(key<2 && m.read_u32(0x238058)!=key)step=0x10; // 1A2D80 toggles either direction.
        if(key>=0x100 && key<0x102 && m.read_u32(0x2380a0)!=key-0x100)step=key==0x100?0x80:0x20;
        if(key>=0x200 && key<0x203){
            if(m.read_u32(0x23815c))return 0;
            const auto row=m.read_u32(0x238170);
            if(row!=key-0x200)step=row<key-0x200?0x40:0x10;
        }
        if(step){click.release=true;return step;}
        chapter_click.reset();return key==0x401?0x4000:0x2000;
    }
    std::filesystem::path edition_slot(std::string_view edition,unsigned index)const{
        require(index<pc_slots,"Invalid PC slot");
        auto folder=root/"local/pc-core/player"/(verify?"verification-saves":"saves");
        if(verify && (!menu_test || extra_test))folder/=report_path().stem();
        if(!chapter_test_folder.empty())folder=chapter_test_folder;
        return folder/(std::string(edition)+"-"+std::to_string(index+1)+".kx3save");
    }
    std::filesystem::path slot_path(unsigned index)const{return edition_slot(program,index);}
    bool saved(std::string_view edition)const{
        for(unsigned i=0;i<pc_slots;++i)if(std::filesystem::is_regular_file(edition_slot(edition,i)))return true;
        const auto found=notes.find(std::string(edition));return found!=notes.end() && !found->second.empty();
    }
    void open_title(){
        editions=source_title_selection(game->memory(),false);lobby=Lobby::home;lobby_focus=0;lobby_press.reset();
        clear_keys();feedback.clear();notes.clear();
        for(const auto& row:editions.rows){
            try{notes[row.program]=ProjectGame::note_slots(root,row.program,edition_slot(row.program,0).parent_path()/(row.program+"-system.dat"));}
            catch(const std::exception& e){feedback=wide(e.what());}
        }
        next=Clock::now()+cycle;if(window)InvalidateRect(window,nullptr,FALSE);
    }
    const wchar_t* edition_title(std::string_view work)const{
        if(work=="sn2")return ui(L"舒普尔旅馆篇",L"Spur Lodge",L"ペンション“シュプール”編");
        if(work=="sn4")return ui(L"监狱岛的童谣篇",L"The Prison Island Children's Song",L"監獄島のわらべ唄編");
        return ui(L"三日月岛事件的真相篇",L"The Truth Behind the Mikazuki Island Incident",L"三日月島事件の真相編");
    }
    bool lobby_available(unsigned i)const{
        if(lobby==Lobby::home)return i==0 || i==2 || (i==1 && std::any_of(editions.rows.begin(),editions.rows.end(),[&](const auto& e){return saved(e.program);}));
        if(lobby==Lobby::new_note)return i<=pc_slots;
        if(lobby==Lobby::slots){
            const auto& work=editions.rows[load_edition].program;
            if(i<pc_slots)return std::filesystem::is_regular_file(edition_slot(work,i));
            const auto found=notes.find(work);return found!=notes.end() && i-pc_slots<found->second.size();
        }
        return i<3;
    }
    void start_edition(std::string chosen,std::optional<unsigned> slot,
                       std::optional<unsigned> new_note={},bool replace=false){
        try{
            const auto record=edition_slot(chosen,0).parent_path()/(chosen+"-system.dat");
            std::unique_ptr<ProjectGame> incoming;
            if(new_note)incoming=ProjectGame::new_note(root,chosen,record,*new_note,replace);
            else if(!slot)incoming=std::make_unique<ProjectGame>(root,chosen);
            else if(*slot<pc_slots)incoming=ProjectGame::load(root,chosen,edition_slot(chosen,*slot));
            else incoming=ProjectGame::load_note(root,chosen,record,notes.at(chosen).at(*slot-pc_slots));
            if(!new_note && (!slot || *slot<pc_slots))incoming->set_system_record_file(record);
            game.swap(incoming);program.swap(chosen);
            try{read_presentation();if(!verify)game->enable_audio_output();}
            catch(...){game.swap(incoming);program.swap(chosen);read_presentation();throw;}
            frames=game->logical_tick();steps=0;frontier.clear();failed_save_input.reset();feedback.clear();has_progress=new_note.has_value() || saved(program);
            next=Clock::now()+cycle;clear_keys();lobby=Lobby::hidden;lobby_press.reset();lobby_buttons.clear();
            refresh_caption();InvalidateRect(window,nullptr,FALSE);
        }catch(const std::exception& e){feedback=wide(e.what());if(!verify)MessageBoxW(window,feedback.c_str(),title,MB_ICONERROR|MB_OK);}
    }
    bool confirm_replace(const wchar_t* question){
        if(verify && modal_reply)SetTimer(window,overwrite_timer,20,nullptr);
        const auto result=MessageBoxW(window,question,title,MB_OKCANCEL|MB_DEFBUTTON2);
        if(verify)KillTimer(window,overwrite_timer);
        return result==IDOK;
    }
    void lobby_select(unsigned index){
        if(!lobby_available(index))return;
        switch(lobby){
        case Lobby::home:
            if(index==2){settings();return;}
            lobby=index==0?Lobby::new_game:Lobby::load_game;editions=source_title_selection(game->memory(),index==1);
            lobby_focus=editions.focus;break;
        case Lobby::new_game:lobby=Lobby::new_note;load_edition=index;lobby_focus=0;break;
        case Lobby::new_note:{
            const auto& chosen=editions.rows[load_edition].program;
            if(!index){start_edition(chosen,{});return;}
            const unsigned slot=index-1;
            const auto& used=notes[chosen];
            const bool replace=std::find(used.begin(),used.end(),slot)!=used.end();
            if(replace && !confirm_replace(ui(L"覆盖这个记忆卡记录并开始新游戏？",L"Replace this memory card record and start a new game?",
                     L"この記録に上書きして、新しく始めますか？")))return;
            start_edition(chosen,{},slot,replace);return;
        }
        case Lobby::load_game:lobby=Lobby::slots;load_edition=index;lobby_focus=0;break;
        case Lobby::slots:start_edition(editions.rows[load_edition].program,index);return;
        default:return;
        }
        if(!lobby_available(lobby_focus)){
            for(unsigned i=0;i<lobby_count();++i)if(lobby_available(i)){lobby_focus=i;break;}
        }
        InvalidateRect(window,nullptr,FALSE);
    }
    void poll_title_pad(){
        if(display_page)return;
        const auto edges=title_edges;title_edges=0;
        if(edges && (lobby==Lobby::new_game || lobby==Lobby::load_game)){
            editions.focus=lobby_focus;
            std::vector<SourceSoundEvent> sounds;
            const auto command=game->title_input(editions,edges,sounds);
            title_mixer.apply(sounds,game->images());
            lobby_focus=editions.focus;
            if(command==TitleAction::accept)lobby_select(lobby_focus);
            else if(command==TitleAction::back){lobby_focus=lobby==Lobby::load_game?1:0;lobby=Lobby::home;}
            InvalidateRect(window,nullptr,FALSE);
        }
    }
    void lobby_key(unsigned key){
        if(lobby==Lobby::new_game || lobby==Lobby::load_game){
            const auto edge=key==VK_ESCAPE?0x4000:physical_key(key);
            if(edge && !title_edges)PostMessageW(window,title_pad_msg,0,0);
            title_edges|=edge;return;
        }
        if(key==VK_BACK || key==VK_ESCAPE || key==VK_PRIOR || key=='K'){
            if(lobby==Lobby::home){PostMessageW(window,WM_CLOSE,0,0);return;}
            if(lobby==Lobby::slots || lobby==Lobby::new_note){lobby=lobby==Lobby::slots?Lobby::load_game:Lobby::new_game;lobby_focus=load_edition;}
            else{lobby_focus=lobby==Lobby::load_game?1:0;lobby=Lobby::home;}
        }else if(key==VK_RETURN || key==VK_SPACE || key==VK_HOME || key=='L')lobby_select(lobby_focus);
        else if(key==VK_UP || key==VK_DOWN){
            const int n=int(lobby_count()),step=key==VK_UP?-1:1;
            for(int i=int(lobby_focus)+step;i>=0 && i<n;i+=step)if(lobby_available(unsigned(i))){lobby_focus=unsigned(i);break;}
        }
        InvalidateRect(window,nullptr,FALSE);
    }
    std::optional<unsigned> lobby_at(POINT pt){
        UpdateWindow(window);
        for(unsigned i=0;i<lobby_buttons.size();++i)if(lobby_available(i) && PtInRect(&lobby_buttons[i],pt))return i;
        return {};
    }
    unsigned lobby_count()const{
        if(lobby==Lobby::home)return 3;
        if(lobby==Lobby::new_note)return pc_slots+1;
        if(lobby!=Lobby::slots)return 3;
        const auto found=notes.find(editions.rows[load_edition].program);
        return pc_slots+unsigned(found==notes.end()?0:found->second.size());
    }
    void draw_title(HDC dc){
        RECT client{};GetClientRect(window,&client);fill(dc,client,rail_color);lobby_buttons.clear();
        const LONG w=client.right,h=client.bottom,margin=std::max(12L,w/12),x=std::max(margin,w/4),right=w-margin;
        draw_ui_text(dc,{margin,h/9,w-margin,h/9+38},ui(L"镰鼬之夜 ×3",L"Kamaitachi no Yoru ×3",L"かまいたちの夜 ×3"),title_font,brass,DT_LEFT|DT_SINGLELINE);
        const wchar_t* heading=lobby==Lobby::home?ui(L"三日月岛事件的真相",L"The Mikazuki Island Incident",L"三日月島事件の真相"):
            lobby==Lobby::slots?edition_title(editions.rows[load_edition].program):
            lobby==Lobby::new_note?ui(L"新游戏记录",L"New game record",L"新しい記録"):ui(L"选择作品",L"Choose a story",L"ゲーム選択");
        draw_ui_text(dc,{x,h/4,right,h/4+50},heading,title_font,ivory,DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);
        const int n=int(lobby_count()),cols=n>5?2:1,rows=(n+cols-1)/cols;
        const LONG top=h/4+56,step=std::clamp((h-70-top)/rows,22L,68L),width=(right-x)/cols;
        for(int i=0;i<n;++i){
            const LONG left=x+(i/rows)*width;
            const RECT rc{left,top+i%rows*step,left+width-(cols==1?0:3),top+(i%rows+1)*step-5};lobby_buttons.push_back(rc);
            const bool active=lobby_available(i);const COLORREF color=lobby_focus==unsigned(i)?brass:active?ivory:slate;
            fill(dc,rc,lobby_focus==unsigned(i)?RGB(36,42,52):RGB(22,30,41));
            if(lobby_focus==unsigned(i))fill(dc,{rc.left,rc.top,rc.left+3,rc.bottom},brass);
            std::wstring label;
            if(lobby==Lobby::home)label=i==2?ui(L"设置",L"Settings",L"設定"):i?ui(L"继续进度",L"Continue",L"続きから"):ui(L"从头开始",L"New game",L"始めから");
            else if(lobby==Lobby::new_note){
                if(!i)label=ui(L"不建卡，直接开始",L"Start without a card record",L"記録を作らずに始める");
                else{
                    const auto& used=notes[editions.rows[load_edition].program];
                    const bool occupied=std::find(used.begin(),used.end(),unsigned(i-1))!=used.end();
                    label=std::wstring(ui(L"记录 ",L"Record ",L"記録 "))+std::to_wstring(i)+
                          (occupied?ui(L" · 已有",L" · in use",L" · 使用中"):ui(L" · 空",L" · empty",L" · 空き"));
                }
            }else if(lobby==Lobby::slots && unsigned(i)<pc_slots)label=std::wstring(ui(L"PC 存档 ",L"PC save ",L"PC セーブ "))+std::to_wstring(i+1);
            else if(lobby==Lobby::slots)label=std::wstring(ui(L"记忆卡存档 ",L"Memory card save ",L"メモリーカード "))+
                std::to_wstring(notes.at(editions.rows[load_edition].program).at(i-pc_slots)+1);
            else label=edition_title(editions.rows[i].program);
            draw_ui_text(dc,{rc.left+16,rc.top,rc.right-8,rc.bottom},label.c_str(),rc.bottom-rc.top>=menu_height+3?menu_font:body,color,DT_LEFT|DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
        }
        draw_ui_text(dc,{x,h-54,right,h-20},ui(L"↑ ↓  选择　　○ 确认　　× 返回　　F6 语言",L"↑ ↓  Select     ○ Confirm     × Back     F6 Language",L"↑ ↓ 選択　　○ 決定　　× 戻る　　F6 言語"),small,slate,DT_LEFT|DT_WORDBREAK);
        draw_location(dc,{x,h-19,right,h-1},title_location());
    }
    void save_slot(unsigned slot){
        const auto state=menu();
        const bool automatic=state.screen==12;
        if(!state.open || (!automatic && (state.screen!=14 || !state.can_request_save)))return;
        struct Pause{Player& p;bool previous;~Pause(){p.settings_open=previous;p.clear_keys();p.next=Clock::now()+cycle;}} pause{*this,settings_open};
        settings_open=true;
        const auto path=slot_path(slot);
        if((!verify || modal_reply) && std::filesystem::exists(path)){
            const auto confirm=automatic?ui(L"覆盖这个槽位并用它自动保存？",L"Replace this slot and use it for autosave?",L"このスロットを上書きしてオートセーブしますか？"):
                ui(L"覆盖这个槽位并退出？",L"Replace this save and quit?",L"このスロットを上書きして終了しますか？");
            if(!confirm_replace(confirm))return;
        }
        try{
            std::filesystem::create_directories(path.parent_path());
            if(automatic)game->save_auto_target(path,slot);else game->save_from_menu(path);
            ++slot_writes;has_progress=true;
            feedback=automatic?ui(L"自动保存槽已设置。",L"Autosave slot set.",L"オートセーブ先を設定しました。"):
                ui(L"进度已保存。",L"Progress saved.",L"セーブが終了しました。");
            if(!verify){MessageBoxW(window,feedback.c_str(),title,MB_OK);if(!automatic)open_title();}
        }catch(const std::exception& e){feedback=wide(e.what());if(!verify)MessageBoxW(window,feedback.c_str(),title,MB_OK|MB_ICONERROR);}
        next=Clock::now()+cycle;InvalidateRect(window,nullptr,FALSE);
    }
    bool load_slot(unsigned slot){
        try{
            auto restored=ProjectGame::load(root,program,slot_path(slot));
            restored->set_system_record_file(slot_path(0).parent_path()/(program+"-system.dat"));
            game.swap(restored);
            try{read_presentation();if(!verify)game->enable_audio_output();}
            catch(...){game.swap(restored);read_presentation();throw;}
            frames=game->logical_tick();steps=0;frontier.clear();failed_save_input.reset();feedback=ui(L"进度已恢复。",L"Progress restored.",L"ロードが終了しました。");
            clear_keys();next=Clock::now()+cycle;refresh_caption();InvalidateRect(window,nullptr,FALSE);
            return true;
        }catch(const std::exception& e){feedback=wide(e.what());if(!verify)MessageBoxW(window,feedback.c_str(),title,MB_OK|MB_ICONERROR);return false;}
    }
    void continue_game(){
        if(!has_progress)return;
        try{notes[program]=ProjectGame::note_slots(root,program,slot_path(0).parent_path()/(program+"-system.dat"));}
        catch(const std::exception& e){feedback=wide(e.what());if(!verify)MessageBoxW(window,feedback.c_str(),title,MB_OK|MB_ICONERROR);}
        clear_keys();settings_open=true;
        HMENU choices=CreatePopupMenu();require(choices!=nullptr,"Could not open Continue menu");
        for(unsigned i=0;i<pc_slots;++i){
            const auto label=std::wstring(ui(L"槽位 ",L"Slot ",L"スロット "))+std::to_wstring(i+1);
            AppendMenuW(choices,MF_STRING|(std::filesystem::is_regular_file(slot_path(i))?0:MF_GRAYED),i+1,label.c_str());
        }
        if(!notes[program].empty())AppendMenuW(choices,MF_SEPARATOR,0,nullptr);
        for(unsigned i=0;i<notes[program].size();++i){
            const auto label=std::wstring(ui(L"记忆卡存档 ",L"Memory card save ",L"メモリーカード "))+std::to_wstring(notes[program][i]+1);
            AppendMenuW(choices,MF_STRING,pc_slots+1+i,label.c_str());
        }
        const auto v=view();POINT at{v.rail.right?12:4,v.rail.bottom/2};ClientToScreen(window,&at);
        const auto chosen=TrackPopupMenu(choices,TPM_RETURNCMD|TPM_NONOTIFY,at.x,at.y,0,window,nullptr);
        DestroyMenu(choices);settings_open=false;
        if(chosen>pc_slots)start_edition(program,chosen-1);
        else if(chosen)SendMessageW(window,WM_COMMAND,continue_slot_message+chosen-1,0);
        next=Clock::now()+cycle;
    }
    std::wstring name(SystemMenuAction action)const{
        switch(action){
        case SystemMenuAction::Timeline:return ui(L"时间图",L"Time chart",L"タイムチャート");
        case SystemMenuAction::Endings:return ui(L"结局列表",L"Endings",L"エンディングリスト");
        case SystemMenuAction::Settings:return ui(L"环境设置",L"Settings",L"環境設定");
        case SystemMenuAction::SaveAndQuit:return ui(L"结束并保存",L"Save and quit",L"ゲーム終了（セーブ）");
        case SystemMenuAction::Memory:return ui(L"记忆卡",L"Memory card",L"メモリーカード");
        case SystemMenuAction::Chapters:return ui(L"章节",L"Chapters",L"チャプター");
        }
        return {};
    }
    std::vector<RailRow> rail_rows(const Layout& l)const{
        std::vector<RailRow> rows;
        if(!l.rail.right)return rows;
        const auto state=menu();
        const auto add=[&](RailCommand command,unsigned value,std::wstring label,bool enabled=true,bool selected=false){
            rows.push_back({command,value,std::move(label),enabled,selected,{}});
        };
        if(!failed_save_input && !state.open && state.controls_visible)return rows;
        if(failed_save_input){
            add(RailCommand::retry_save,0,ui(L"重试保存 · F5",L"Retry save · F5",L"セーブを再試行 · F5"));
        }else if(!state.open && state.notice_text_address){
            add(RailCommand::unavailable,0,system_string(state.notice_text_address),false);
            add(RailCommand::interval_pad,0x2000,ui(L"继续",L"Continue",L"続ける"));
        }else if(!state.open){
            const bool available=system_menu_available(game->memory(),game->runtime().manager).value_or(false);
            const auto action=state.can_stop_auto?ui(L"停止自动推进  △",L"Stop auto  △",L"自動送り停止  △"):
                ui(L"游戏菜单  △",L"Game menu  △",L"ゲームメニュー  △");
            add(RailCommand::open,0,action,frontier.empty() && (available || state.can_stop_auto));
            add(RailCommand::display,0,ui(L"设置 · F1",L"Settings · F1",L"設定 · F1"));
            add(RailCommand::resume,0,ui(L"继续进度",L"Continue",L"つづきから"),has_progress);
            if(frontier.empty() && available)
                add(RailCommand::interval_pad,8,ui(L"自动推进  T",L"Auto advance  T",L"自動送り  T"));
            if(frontier.empty() && brightness_control_available(game->memory(),game->runtime().manager).value_or(false)){
                if(state.brightness_visible){
                    add(RailCommand::brightness_pad,0x80,std::wstring(system_string(0x2072e3))+L"  ←",state.brightness_level<100);
                    add(RailCommand::brightness_pad,0x20,std::wstring(system_string(0x2072ee))+L"  →",state.brightness_level>0);
                }else add(RailCommand::brightness_pad,0x80,ui(L"调整亮度",L"Adjust brightness",L"明るさを調節"));
            }
            if(mouse_inspection)
                add(RailCommand::inspect_hold,0,ui(L"返回剧情",L"Return to story",L"シナリオに戻る"));
            else if(frontier.empty() && !game->memory().read_u32(game->runtime().manager+0x44) &&
                    inspection_control_available(game->memory(),game->runtime().manager).value_or(false))
                add(RailCommand::inspect_hold,1,ui(L"查看背景 · End",L"View scene · End",L"背景を見る · End"));
        }else if(state.interval_level){
            add(RailCommand::unavailable,0,std::wstring(system_string(0x20d630))+L" · "+std::to_wstring(state.interval_level)+L" / 5",false);
            add(RailCommand::interval_pad,0x80,std::wstring(system_string(0x20d678))+L"  ←",state.interval_ready && state.interval_level>1);
            add(RailCommand::interval_pad,0x20,std::wstring(system_string(0x20d688))+L"  →",state.interval_ready && state.interval_level<5);
            add(RailCommand::interval_pad,0x2000,ui(L"确定",L"Confirm",L"決定"),state.interval_ready);
            add(RailCommand::interval_pad,0x4000,ui(L"取消",L"Cancel",L"取消"),state.interval_ready);
        }else if(state.screen==0){
            for(unsigned i=0;i<state.actions.size();++i){
                const auto a=state.actions[i];
                add(RailCommand::source,i,name(a),true,state.focus==i);
            }
            add(RailCommand::back,0,ui(L"返回游戏",L"Resume game",L"ゲームに戻る"));
        }else{
            if(!use_original_card && (state.screen==12 || (state.screen==14 && state.can_request_save))){
                const unsigned first=selected_slot/slots_per_page*slots_per_page;
                for(unsigned i=first;i<first+slots_per_page;++i)add(RailCommand::save_slot,i,
                    std::wstring(state.screen==12?ui(L"自动保存槽 ",L"Autosave slot ",L"オートセーブ先 "):
                    ui(L"保存到槽位 ",L"Save to slot ",L"セーブ先 "))+std::to_wstring(i+1),true,selected_slot==i);
                add(RailCommand::slot_page,first?0:slots_per_page,first?
                    ui(L"查看槽位 1–5",L"Show slots 1–5",L"スロット 1–5"):
                    ui(L"查看槽位 6–10",L"Show slots 6–10",L"スロット 6–10"));
                add(RailCommand::original_card,0,
                    ui(L"原版记忆卡 · Tab",L"Memory card · Tab",L"メモリーカード · Tab"));
            }else if(state.screen==4){
                add(RailCommand::display,0,ui(L"设置 · F1",L"Settings · F1",L"設定 · F1"));
            }else if(state.screen==1){
                add(RailCommand::unavailable,0,name(SystemMenuAction::Timeline),false);
            }else if(state.screen==2){
                add(RailCommand::unavailable,0,name(SystemMenuAction::Chapters),false);
            }else if(state.screen==3){
                add(RailCommand::unavailable,0,name(SystemMenuAction::Endings),false);
            }else if(card_controls_open()){
                add(RailCommand::unavailable,0,chapter_open()?ui(L"章末存档",L"Chapter save",L"章末セーブ"):
                    ui(L"记忆卡",L"Memory card",L"メモリーカード"),false);
                add(RailCommand::display,0,ui(L"设置 · F1",L"Settings · F1",L"設定 · F1"));
            }else add(RailCommand::unavailable,0,ui(L"原资料页待恢复",L"Page in development",L"復元中"),false);
            if(!card_controls_open())add(RailCommand::back,0,ui(L"返回菜单",L"Back to menu",L"メニューに戻る"));
        }
        const int height=l.rail.bottom,top=height<460?height/5:height*32/100;
        const int spacing=std::min(std::clamp(height*39/100/int(rows.size()),34,84),
            std::max(1,(height-92-top)/int(rows.size())));
        for(unsigned i=0;i<rows.size();++i){
            const LONG y=LONG(top+i*spacing);
            rows[i].rect={0,y,l.rail.right,y+spacing-2};
        }
        return rows;
    }
    std::optional<unsigned> rail_at(POINT pt)const{
        const auto rows=rail_rows(view());
        for(unsigned i=0;i<rows.size();++i)if(rows[i].enabled && PtInRect(&rows[i].rect,pt))return i;
        return {};
    }
    void rail_action(unsigned index){
        const auto rows=rail_rows(view());if(index>=rows.size() || !rows[index].enabled)return;
        const auto& row=rows[index];
        switch(row.command){
        case RailCommand::open:pressed|=0x1000;break;
        case RailCommand::interval_pad:case RailCommand::brightness_pad:pressed|=std::uint16_t(row.value);break;
        case RailCommand::inspect_hold:mouse_inspection=row.value!=0;break;
        case RailCommand::source:menu_hover=row.value;menu_click=true;break;
        case RailCommand::save_slot:save_slot(row.value);break;
        case RailCommand::original_card:use_original_card=true;clear_keys();InvalidateRect(window,nullptr,FALSE);break;
        case RailCommand::slot_page:selected_slot=row.value;InvalidateRect(window,nullptr,FALSE);break;
        case RailCommand::retry_save:retry_save();break;
        case RailCommand::back:pressed|=0x4000;break;
        case RailCommand::display:settings();break;
        case RailCommand::resume:continue_game();break;
        case RailCommand::unavailable:break;
        }
    }
    void refresh_scene_pixels(){
        ++image_revision;
        scene_pixels.clear();if(!scene)return;
        require(scene->width && scene->height && scene->rgba.size()==std::size_t(scene->width)*scene->height*4,
                "Invalid committed image");
        scene_pixels.reserve(scene->rgba.size()/4);
        for(u32 y=0;y<scene->height;++y)for(u32 x=0;x<scene->width;++x) {
            const auto* rgba=&scene->rgba[(std::size_t(y)*scene->width+x)*4];
            scene_pixels.push_back(scene_pixel(rgba,y,scans && !scale2x,scene_darkening));
        }
        if(scale2x){
            scene_pixels=scale2x_pixels(scene_pixels,scene->width,scene->height);
            if(scans){
                const std::size_t pitch=std::size_t(scene->width)*2;
                for(unsigned y=0;y<scene->height*2;++y)if((y/2)&1)
                    for(auto& px:std::span(scene_pixels).subspan(y*pitch,pitch)){
                        const auto dim=[&](unsigned shift){return (((px>>shift)&255)*195/255)<<shift;};
                        px=dim(0)|dim(8)|dim(16);
                    }
            }
        }
    }
    void read_presentation(){
        const auto active=game->actor_choice();
        if(active.open){
            if(actor_art.empty())actor_art=read_disc_resource(root,"PANEL/hrsel.dat","c082f7c5efeb512abf48fca6813f691c04c1448748a5c185c32d2caad13a5108",2926592);
            if(!actors.open || actors.opacity!=active.opacity || actors.highlight!=active.highlight || actors.portrait!=active.portrait)
                actor_overlay=render_actor_panel(active,actor_art);
        }else actor_overlay={};
        actors=active;
        const auto current=game->scene_frame();
        had_prepared_only|=!game->images().prepared().empty() && !current;
        const auto darkening=original_background_darkening(game->memory()).value_or(current==scene?scene_darkening:0);
        if(current!=scene || darkening!=scene_darkening){scene=current;scene_darkening=darkening;refresh_scene_pixels();}
        const auto& m=game->memory();
        mystery_overlay=render_mystery_panel(m);
        const auto font=m.read_u32(game->runtime().manager+0x3c);
        glyph_count=0;
        for(unsigned off:{8u,12u}){
            const auto channel=m.read_u32(font+off);
            if(channel)glyph_count+=m.read_u32(m.read_u32(channel)+4);
        }
        // 112DC0 hides the original font during background inspection. The
        // glyph events remain owned by the VM and reappear on release.
        if(m.read_u32(font+0x28)){translated={};letters={};marks={};return;}
        translated=localize_story_page(m,m.read_u32(game->runtime().manager+0x38),language,game->visible_text_events(),program);
        for(const auto& id:translated.pending)if(missing.insert(id).second && !verify){
            std::ofstream output(missing_file,std::ios::app);output<<id<<'\n';
            require(bool(output),"Could not record untranslated source ID");
        }
        letters={};marks={};if(!glyph_count)return;
        const std::array<TextAtlasResource,2> atlas={TextAtlasResource{0,mark},TextAtlasResource{4,love}};
        if(language==StoryLanguage::japanese)letters=render_text_layer(m,font,atlas);
        else marks=render_text_layer(m,font,atlas,TextLayerParts::artwork);
    }
    void preference(const wchar_t* key,unsigned value){
        if(verify && !prefs_test)return;
        const auto text=std::to_wstring(value);
        require(WritePrivateProfileStringW(L"display",key,text.c_str(),preferences.c_str())!=0,
                "Could not persist player display setting");
    }
    void change_language(StoryLanguage next_language){
        if(language==next_language)return;
        language=next_language;
        preference(L"language",unsigned(language));
        read_presentation();refresh_caption();InvalidateRect(window,nullptr,FALSE);
    }
    void retry_save(){
        if(!failed_save_input)return;
        clear_keys();frontier.clear();next=Clock::now();
    }
    void tick(){
        if(!frontier.empty())return;
        timing("tick_begin");
        ChoiceInput input;
        const auto screen=game->memory().read_u32(0x2388e8);
        if(use_original_card && (!game->memory().read_u32(0x2388cc) || (screen!=14 && screen!=12)))use_original_card=false;
        input.original_card_menu=use_original_card;
        input.held=pressed;pressed=0;
        if(mouse_inspection)input.held|=0x200; // R2 remains down until the player leaves inspection.
        for(unsigned k=0;k<keys.size();++k)if(keys[k])input.held|=physical_key(k);
        if(input.held)chapter_click.reset();
        else input.held=chapter_pad();
        if(mystery_target){
            const auto& m=game->memory();
            const int current=mystery::selected(m);
            if(input.held || current<0 || m.read_u32(mystery::descriptor)!=mystery_source)mystery_target.reset();
            else if(!m.read_u16(0x238700)){
                if(current!=*mystery_target)input.held=0x8000; // Original next-eligible action.
                else {input.held=0x2000;mystery_target.reset();}
            }
        }
        if(pending_choice)input.mouse_index=static_cast<int>(*pending_choice);
        input.mouse_confirm=choice_confirm;
        if(menu_hover)input.menu_index=int(*menu_hover);
        input.menu_confirm=menu_click;menu_hover.reset();menu_click=false;
        if(name_hover)input.name_index=int(*name_hover);
        input.name_confirm=name_click;name_hover.reset();name_click=false;
        if(actor_hover)input.actor_index=int(*actor_hover);
        input.actor_confirm=actor_click;actor_hover.reset();actor_click=false;
        pending_choice.reset();choice_confirm=false;
        if(failed_save_input){input=*failed_save_input;failed_save_input.reset();}
        try{
            auto result=game->advance(input);
            if(chapter_open() && game->memory().read_u32(0x235b4c)==1)has_progress=true;
            last_system_request=result.system_record_requested;
            ++frames;steps+=result.script_steps;
            if(input.original_card_menu && game->memory().read_u32(0x238680)){
                use_original_card=false;open_title();return;
            }
        }catch(const CardWriteError& e){
            failed_save_input=input;frontier=e.what();clear_keys();
        }catch(const std::system_error& e){
            if(game->memory().read_u32(0x239fe8) && game->memory().read_u32(0x239fa4)==1)failed_save_input=input;
            frontier=e.what();clear_keys();
        }catch(const std::exception& e){frontier=e.what();clear_keys();}
        // Loader and manager may have separate transactions in the same host
        // tick. Inspect only their published state, including after rollback.
        timing("advanced");
        try{read_presentation();}catch(const std::exception& e){letters={};frontier=std::string("Presentation: ")+e.what();}
        timing("prepared");
        if(!frontier.empty())refresh_caption();
        InvalidateRect(window,nullptr,FALSE);
    }
    bool running_clock() const{
        return !verify && !IsIconic(window) &&
            ((lobby==Lobby::hidden && !settings_open && frontier.empty()) || !title_mixer.voices().empty());
    }
    void timer(){
        const auto now=Clock::now();
        for(unsigned i=0;i<4 && now>=next && running_clock();++i){
            next+=cycle;
            if(!title_mixer.voices().empty()){
                try{
                    const auto samples=title_mixer.mix_tick();
                    if(!title_output)title_output=std::make_unique<WaveOutput>();
                    title_output->submit(samples);
                }catch(const std::exception& e){
                    feedback=wide(e.what());title_output.reset();title_mixer=ProjectMixer{};
                }
            }
            if(lobby==Lobby::hidden && !settings_open && frontier.empty())tick();
        }
        if(now-next>cycle*4)next=now+cycle;
    }
    void toggle_fullscreen(){
        if(fullscreen){
            SetWindowLongPtrW(window,GWL_STYLE,style);SetWindowPlacement(window,&placement);
            SetWindowPos(window,nullptr,0,0,0,0,SWP_NOZORDER|SWP_NOSIZE|SWP_NOMOVE|SWP_FRAMECHANGED);
        }else{
            style=GetWindowLongPtrW(window,GWL_STYLE);GetWindowPlacement(window,&placement);
            MONITORINFO mi{sizeof(MONITORINFO)};GetMonitorInfoW(MonitorFromWindow(window,MONITOR_DEFAULTTONEAREST),&mi);
            SetWindowLongPtrW(window,GWL_STYLE,(style&~WS_OVERLAPPEDWINDOW)|WS_POPUP);
            const auto r=mi.rcMonitor;SetWindowPos(window,HWND_TOP,r.left,r.top,r.right-r.left,r.bottom-r.top,SWP_FRAMECHANGED);
        }
        fullscreen=!fullscreen;InvalidateRect(window,nullptr,FALSE);
    }
    void setting(unsigned id){
        if(id==1){smooth=!smooth;preference(L"smooth",smooth);}
        if(id==2){scans=!scans;preference(L"scanlines",scans);refresh_scene_pixels();}
        if(id==3)toggle_fullscreen();
        if(id>=4 && id<=6)change_language(static_cast<StoryLanguage>(id-4));
        if(id==7)game->enable_audio_output();
        if(id==8){scale2x=!scale2x;preference(L"scale2x",scale2x);refresh_scene_pixels();}
        InvalidateRect(window,nullptr,FALSE);
    }
    struct DisplayRow { unsigned action;std::wstring label,value; };
    std::vector<DisplayRow> display_rows()const{
        if(display_about)return {{13,ui(L"返回设置",L"Back to settings",L"設定に戻る"),L"×"}};
        const wchar_t* locales[]={L"日本語",L"简体中文",L"English"};
        const auto on=[&](bool value){return value?ui(L"开",L"On",L"入"):ui(L"关",L"Off",L"切");};
        std::vector<DisplayRow> rows{
            {10,ui(L"文字语言",L"Text language",L"表示言語"),locales[unsigned(language)]},
            {11,ui(L"画面缩放",L"Image scaling",L"拡大方式"),scale2x?L"Scale2x":smooth?ui(L"平滑",L"Smooth",L"スムーズ"):ui(L"原像素",L"Sharp",L"ドット")},
            {2,ui(L"扫描线",L"Scanlines",L"走査線"),on(scans)},
            {3,ui(L"全屏显示",L"Fullscreen",L"全画面"),on(fullscreen)},
            {9,ui(L"保存截图",L"Save screenshot",L"画面を保存"),L"F12"}
        };
        if(!game->audio_output_error().empty())rows.push_back({7,ui(L"重试音频输出",L"Retry audio output",L"音声出力を再試行"),L""});
        rows.push_back({12,ui(L"关于与贡献",L"About & credits",L"このプログラムについて"),L""});
        rows.push_back({0,ui(L"返回",L"Back",L"戻る"),L"×"});
        return rows;
    }
    void close_settings(){
        // Consume the modal key through key-up; closing must not confirm a story choice.
        for(unsigned k=0;k<keys.size();++k)display_key_release[k]=display_key_release[k] || keys[k];
        clear_keys();display_press.reset();
        if(GetCapture()==window)ReleaseCapture();
        settings_open=false;display_page=false;display_about=false;mouse_inspection=display_inspection;
        next=Clock::now()+cycle;InvalidateRect(window,nullptr,FALSE);
    }
    void settings(){
        if(display_page){close_settings();return;}
        display_inspection=mouse_inspection;
        for(unsigned k=0;k<keys.size();++k)display_key_release[k]=display_key_release[k] || keys[k];
        clear_keys();display_press.reset();
        if(GetCapture()==window)ReleaseCapture();
        settings_open=true;display_page=true;display_about=false;display_focus=0;
        next=Clock::now()+cycle;InvalidateRect(window,nullptr,FALSE);
    }
    void display_activate(unsigned index,int direction=1){
        const auto rows=display_rows();if(index>=rows.size())return;
        display_focus=index;const auto action=rows[index].action;
        if(action==0){close_settings();return;}
        if(action==12){display_about=true;about_scroll=0;display_focus=0;InvalidateRect(window,nullptr,FALSE);return;}
        if(action==13){
            display_about=false;const auto main=display_rows();
            for(unsigned i=0;i<main.size();++i)if(main[i].action==12)display_focus=i;
            InvalidateRect(window,nullptr,FALSE);return;
        }
        if(action==10)change_language(static_cast<StoryLanguage>((int(language)+3+direction)%3));
        else if(action==11){
            const int current=scale2x?2:smooth?1:0,next=(current+3+direction)%3;
            smooth=next==1;scale2x=next==2;
            preference(L"smooth",smooth);preference(L"scale2x",scale2x);refresh_scene_pixels();
        }else if(action==9)capture_screenshot();
        else setting(action);
        display_focus=std::min(display_focus,unsigned(display_rows().size()-1));
        InvalidateRect(window,nullptr,FALSE);
    }
    void display_key(unsigned key){
        if(display_about && (key==VK_ESCAPE || key==VK_BACK || key=='K')){display_activate(0);return;}
        if(key==VK_ESCAPE || key==VK_BACK || key=='K' || key==VK_F1){close_settings();return;}
        if(display_about && (key==VK_UP || key==VK_DOWN || key==VK_PRIOR || key==VK_NEXT || key==VK_HOME || key==VK_END)){
            if(key==VK_HOME)about_scroll=0;
            else if(key==VK_END)about_scroll=about_scroll_max;
            else scroll_about((key==VK_UP || key==VK_PRIOR?-1:1)*(key==VK_PRIOR || key==VK_NEXT?160:40));
            InvalidateRect(window,nullptr,FALSE);return;
        }
        const auto rows=display_rows();
        if(key==VK_UP || key==VK_DOWN || key==VK_TAB){
            const bool up=key==VK_UP || (key==VK_TAB && (GetKeyState(VK_SHIFT)&0x8000));
            display_focus=(display_focus+unsigned(rows.size())+(up?-1:1))%unsigned(rows.size());
        }else if(key==VK_RETURN || key==VK_SPACE || key=='L')display_activate(display_focus);
        else if((key==VK_LEFT || key==VK_RIGHT) && rows[display_focus].action>=1 && rows[display_focus].action<=11 && rows[display_focus].action!=9 && rows[display_focus].action!=7)
            display_activate(display_focus,key==VK_LEFT?-1:1);
        else if(key==VK_F11)setting(3);
        else if(key==VK_F2)setting(1);
        else if(key==VK_F3)setting(2);
        else if(key==VK_F4)setting(8);
        else if(key==VK_F6)change_language(static_cast<StoryLanguage>((unsigned(language)+1)%3));
        else if(key==VK_F12)capture_screenshot();
        InvalidateRect(window,nullptr,FALSE);
    }
    void scroll_about(LONG delta){
        about_scroll=std::clamp(about_scroll+delta,0L,about_scroll_max);InvalidateRect(window,nullptr,FALSE);
    }
    void draw_about(HDC dc,LONG left,LONG top,LONG right,LONG bottom){
        const wchar_t* paragraphs[]={
            ui(L"本程序仅供技术交流，禁止商用。请自行准备游戏原盘镜像（ISO）进行游戏；本程序不附带游戏光盘素材。",
               L"For technical exchange only. Commercial use is prohibited. Please provide an ISO image of your original game disc to play. Game disc assets are not included.",
               L"本プログラムは技術交流専用です。商用利用は禁止します。プレイにはご自身で用意した原版ディスクのISOイメージが必要です。ゲーム素材は同梱していません。"),
            ui(L"项目贡献",L"Project contributions",L"プロジェクトへの貢献"),
            ui(L"wwesun2000 — 项目发起、目标与方向决策、试玩及反馈。",L"wwesun2000 — Project initiation, goals and direction, playtesting and feedback.",L"wwesun2000 — 企画、目標と方針の決定、プレイテストとフィードバック。"),
            ui(L"OpenAI Codex — 逆向分析、原生移植开发、中文翻译、集成与验证；Astra 负责核心分析与实现，Sol 协助测试及文本工作。",L"OpenAI Codex — Reverse engineering, native port development, Chinese translation, integration and validation. Astra: core analysis and implementation; Sol: testing and text work.",L"OpenAI Codex — 解析、ネイティブ移植、中国語翻訳、統合と検証。Astra：中核の解析と実装。Sol：テストとテキスト作業。"),
            ui(L"Claude — Opus 提供技术咨询；Sonnet 协助英文翻译与措辞复核。",L"Claude — Opus: technical consultation. Sonnet: English translation and wording review.",L"Claude — Opus：技術相談。Sonnet：英訳と表現の確認。"),
            ui(L"Gemini — 中文译稿润色与校对。",L"Gemini — Chinese translation polishing and proofreading.",L"Gemini — 中国語訳の推敲と校正。"),
            ui(L"以上为本移植项目的协作贡献。原作及其素材权利归相应权利人所有。",L"These credits describe contributions to this port. Rights to the original game and its assets remain with their respective owners.",L"以上は本移植プロジェクトへの貢献です。原作および素材の権利は各権利者に帰属します。")
        };
        const LONG first=top+44,last=bottom-78;
        std::vector<LONG> heights;LONG total=0;
        const auto previous=SelectObject(dc,body);
        for(const auto text:paragraphs){RECT measured{0,0,right-left-14,0};DrawTextW(dc,text,-1,&measured,DT_CALCRECT|DT_WORDBREAK|DT_NOPREFIX);heights.push_back(measured.bottom+12);total+=measured.bottom+12;}
        SelectObject(dc,previous);
        about_scroll_max=std::max(0L,total-(last-first));about_scroll=std::clamp(about_scroll,0L,about_scroll_max);
        const int saved=SaveDC(dc);IntersectClipRect(dc,left,first,right,last);
        LONG y=first-about_scroll;
        for(unsigned i=0;i<heights.size();++i){draw_ui_text(dc,{left,y,right-14,y+heights[i]},paragraphs[i],body,i==1?brass:ivory,DT_LEFT|DT_WORDBREAK);y+=heights[i];}
        RestoreDC(dc,saved);
        if(about_scroll_max){
            fill(dc,{right-4,first,right,last},RGB(36,42,52));
            const LONG track=last-first,thumb=std::max(16L,track*track/total),pos=first+(track-thumb)*about_scroll/about_scroll_max;
            fill(dc,{right-4,pos,right,pos+thumb},brass);
        }
        RECT back{left,bottom-66,right,bottom-34};display_buttons.push_back(back);fill(dc,back,RGB(36,42,52));
        fill(dc,{left,back.top,left+3,back.bottom},brass);
        draw_ui_text(dc,{left+11,back.top,right-10,back.bottom},ui(L"返回设置",L"Back to settings",L"設定に戻る"),body,brass,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
        draw_ui_text(dc,{left,bottom-31,right,bottom-13},ui(L"↑ ↓ / 滚轮 浏览   ○ / × 返回",L"↑ ↓ / Wheel Scroll   ○ / × Back",L"↑ ↓ / ホイール スクロール   ○ / × 戻る"),small,slate,DT_SINGLELINE|DT_END_ELLIPSIS);
    }
    std::optional<unsigned> display_at(POINT pt){
        UpdateWindow(window);
        for(unsigned i=0;i<display_buttons.size();++i)if(PtInRect(&display_buttons[i],pt))return i;
        return {};
    }
    void draw_display_settings(HDC dc,const Layout& l){
        RECT client{};GetClientRect(window,&client);fill(dc,client,rail_color);display_buttons.clear();
        auto stage=l.screen;
        if(l.rail.right){
            draw_rail_title(dc,l.rail.right,l.rail.bottom);
            fill(dc,{l.rail.right-1,0,l.rail.right,l.rail.bottom},RGB(104,85,63));
            draw_ui_text(dc,{12,l.rail.bottom/3,l.rail.right-12,l.rail.bottom/3+60},
                ui(L"设置",L"Settings",L"設定"),menu_font,brass,DT_CENTER|DT_WORDBREAK);
        }else stage=client;
        const LONG w=stage.right-stage.left,h=stage.bottom-stage.top,pad=std::max(10L,w/20);
        const LONG left=stage.left+pad,right=stage.right-pad,top=stage.top+std::max(12L,h/16);
        draw_ui_text(dc,{left,top,right,top+36},display_about?ui(L"关于与贡献",L"About & credits",L"このプログラムについて"):ui(L"环境设置",L"Settings",L"環境設定"),title_font,ivory,DT_LEFT|DT_SINGLELINE);
        if(display_about){draw_about(dc,left,top,right,stage.bottom);draw_location(dc,{left,stage.bottom-13,right,stage.bottom},lobby==Lobby::hidden?location_code(menu()):title_location());return;}
        const auto rows=display_rows();
        const LONG first=top+44,step=std::clamp((stage.bottom-first-56)/LONG(rows.size()),20L,62L);
        for(unsigned i=0;i<rows.size();++i){
            const LONG y=first+LONG(i)*step;const RECT rc{left,y,right,y+step-3};display_buttons.push_back(rc);
            const bool selected=i==display_focus;
            fill(dc,rc,selected?RGB(36,42,52):RGB(22,30,41));
            if(selected)fill(dc,{left,y,left+3,rc.bottom},brass);
            const LONG split=left+(right-left)*61/100;
            const auto font=step>=menu_height+5?menu_font:body;
            draw_ui_text(dc,{left+11,y,split-5,rc.bottom},rows[i].label.c_str(),font,selected?brass:ivory,DT_LEFT|DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
            draw_ui_text(dc,{split,y,right-10,rc.bottom},rows[i].value.c_str(),font,brass,DT_RIGHT|DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
        }
        const auto notice=!game->audio_output_error().empty()?wide(game->audio_output_error()):
            !game->record_export_error().empty()?std::wstring(ui(L"进度已保存，记录副本待同步。",L"Progress saved; bank export pending.",L"進捗を保存しました。原記録の書き出しは保留中です。")):feedback;
        if(!notice.empty())draw_ui_text(dc,{left,stage.bottom-53,right,stage.bottom-33},notice.c_str(),small,brass,DT_SINGLELINE|DT_END_ELLIPSIS);
        draw_ui_text(dc,{left,stage.bottom-31,right,stage.bottom-13},
            ui(L"↑ ↓ 选择   ← → 调整   ○ 确认   × 返回",L"↑ ↓ Select   ← → Adjust   ○ Confirm   × Back",L"↑ ↓ 選択   ← → 変更   ○ 決定   × 戻る"),small,slate,DT_SINGLELINE|DT_END_ELLIPSIS);
        draw_location(dc,{left,stage.bottom-13,right,stage.bottom},lobby==Lobby::hidden?location_code(menu()):title_location());
    }
    std::optional<u32> option(POINT p){
        const auto stage=view().screen;if(!PtInRect(&stage,p))return {};
        if(language!=StoryLanguage::japanese){
            const auto& m=game->memory();const auto ctx=m.read_u32(game->runtime().manager+0x40);
            if(m.read_u32(m.read_u32(ctx))!=0x11e748)return {};
            UpdateWindow(window);
            for(const auto& item:translated_options)if(PtInRect(&item.rect,p))return item.index;
            return {};
        }
        return source_choice_at(game->memory(),game->runtime().manager,
            (p.x-stage.left)*640/(stage.right-stage.left),(p.y-stage.top)*448/(stage.bottom-stage.top));
    }
    void draw_story(HDC dc,RECT s){
        const bool credits_active=game->memory().read_u32(0x236824)!=0;
        const auto letter_blur=game->text_blur();
        const bool cacheable=letter_blur.empty() && !credits_active && language!=StoryLanguage::japanese && marks.rgba.empty();
        const bool visible=glyph_count && !game->memory().read_u32(game->memory().read_u32(game->runtime().manager+0x3c)+0x28);
        auto& cache=story_cache;
        if(cacheable && cache.valid && EqualRect(&s,&cache.bounds) && cache.image==image_revision &&
           cache.filtered==smooth && cache.visible==visible && cache.lines==translated.lines &&
           BitBlt(dc,s.left,s.top,s.right-s.left,s.bottom-s.top,cache.dc,0,0,SRCCOPY))return;
        cache.valid=false;
        if(scene){
            const auto factor=scale2x?2u:1u;
            const int image_w=int(scene->width*factor),image_h=int(scene->height*factor);
            draw_scene_surface(dc,s,image_w,image_h,scene_pixels.data(),smooth);
        }
        translated_options.clear();
        if(!letter_blur.empty() && scene && visible){
            RasterFrame ink;
            if(language==StoryLanguage::japanese){ink=letters;++original_text_paints;}
            else {
                ink=raster_story_translation(dc,translated.lines,translated_options);++translated_text_paints;
                if(!marks.rgba.empty()){
                    require(marks.rgba.size()==ink.rgba.size(),"Text artwork surface size changed");
                    for(std::size_t i=0;i<ink.rgba.size();i+=4){
                        const unsigned a=marks.rgba[i+3],b=ink.rgba[i+3],weight=a*255+b*(255-a);
                        if(!a || !weight)continue;
                        for(unsigned c=0;c<3;++c)ink.rgba[i+c]=std::uint8_t((unsigned(marks.rgba[i+c])*a*255+
                            unsigned(ink.rgba[i+c])*b*(255-a)+weight/2)/weight);
                        ink.rgba[i+3]=std::uint8_t((weight+127)/255);
                    }
                }
                for(auto& hit:translated_options){
                    hit.rect={s.left+MulDiv(hit.rect.left,s.right-s.left,640),s.top+MulDiv(hit.rect.top,s.bottom-s.top,448),
                              s.left+MulDiv(hit.rect.right,s.right-s.left,640),s.top+MulDiv(hit.rect.bottom,s.bottom-s.top,448)};
                }
            }
            if(!ink.rgba.empty()){
                RasterFrame output=*scene;
                for(unsigned y=0;y<448;++y)for(unsigned x=0;x<640;++x){auto* pixel=output.rgba.data()+4*(y*640+x);
                    const auto rgb=scene_pixel(pixel,y,scans,scene_darkening);pixel[0]=rgb>>16;pixel[1]=rgb>>8;pixel[2]=rgb;}
                for(unsigned field=0;field<2;++field)for(const auto& sprite:letter_blur)if(sprite.alpha)
                    draw_field_sprite(output,std::span<const std::uint8_t>(ink.rgba).subspan(field*2560),5120,field,
                                      sprite.coordinates.xy,sprite.coordinates.uv,sprite.alpha,true);
                std::vector<u32> pixels(640*448);
                for(std::size_t i=0;i<pixels.size();++i){const auto* p=output.rgba.data()+4*i;pixels[i]=(u32(p[0])<<16)|(u32(p[1])<<8)|p[2];}
                if(scale2x)pixels=scale2x_pixels(pixels,640,448);
                draw_scene_surface(dc,s,scale2x?1280:640,scale2x?896:448,pixels.data(),smooth);
            }
        }else if(language==StoryLanguage::japanese){
            if(!letters.rgba.empty()){draw_letters(dc,s,letters);++original_text_paints;}
        }else if(visible){
            if(!marks.rgba.empty())draw_letters(dc,s,marks);
            translated_text_paints+=draw_story_translation(dc,s,translated.lines,translated_options);
        }
        if(credits_active)draw_staff(dc,s);
        if(cacheable && cache.capture(dc,s)){
            cache.image=image_revision;cache.filtered=smooth;cache.visible=visible;
            cache.lines=translated.lines;cache.valid=true;
        }
    }
    std::wstring staff_text(const credits::Line& line)const{
        if(language!=StoryLanguage::japanese){
            const auto match=std::find_if(std::begin(staff_labels),std::end(staff_labels),[&](const auto& label){
                return program==label.program && line.offset==label.offset && line.original==label.bytes;
            });
            if(match!=std::end(staff_labels))return language==StoryLanguage::chinese?match->zh:match->en;
        }
        return wide(line.original,932);
    }
    void draw_staff(HDC dc,RECT stage){
        const auto state=SaveDC(dc);
        IntersectClipRect(dc,stage.left,stage.top,stage.right,stage.bottom);
        SetBkMode(dc,TRANSPARENT);SetTextColor(dc,ivory);
        int previous_end=stage.left;
        for(const auto& line:credits::visible_lines(game->memory())){
            const auto text=staff_text(line);if(text.empty())continue;
            const int height=std::max(1,MulDiv(line.size,stage.bottom-stage.top,448));
            auto font=create_ui_font(height,FW_NORMAL);
            auto prior=SelectObject(dc,font);SIZE extent{};
            GetTextExtentPoint32W(dc,text.data(),int(text.size()),&extent);
            const int anchor=stage.left+MulDiv(line.anchor,stage.right-stage.left,640);
            const int available=line.alignment==0?2*std::min(anchor-stage.left,stage.right-anchor):
                                line.alignment==2?anchor-stage.left:stage.right-(line.alignment==1?anchor:previous_end);
            if(available>0 && extent.cx>available){
                SelectObject(dc,prior);DeleteObject(font);
                font=create_ui_font(std::max(1,MulDiv(height,available,extent.cx)),FW_NORMAL);
                SelectObject(dc,font);GetTextExtentPoint32W(dc,text.data(),int(text.size()),&extent);
            }
            const int x=line.alignment==0?anchor-extent.cx/2:line.alignment==2?anchor-extent.cx:
                        line.alignment==1?anchor:previous_end;
            TextOutW(dc,x,stage.top+MulDiv(line.y,stage.bottom-stage.top,448),text.data(),int(text.size()));
            previous_end=x+extent.cx;SelectObject(dc,prior);DeleteObject(font);
        }
        RestoreDC(dc,state);
    }
    void paint(HDC dc){
        const auto l=view();
        const int height=std::clamp<int>(l.rail.bottom/31,18,36);
        if(height!=menu_height){
            if(menu_font)DeleteObject(menu_font);
            if(locator_font)DeleteObject(locator_font);
            menu_font=create_ui_font(height,FW_NORMAL);
            locator_font=create_ui_font(std::clamp(height/2,11,15),FW_NORMAL,L"Consolas");
            menu_height=height;
        }
        if(display_page){draw_display_settings(dc,l);return;}
        if(lobby!=Lobby::hidden){draw_title(dc);return;}
        const auto s=l.screen;
        RECT client{};GetClientRect(window,&client);FillRect(dc,&client,static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
        draw_story(dc,s);
        if(const auto foreground=game->foreground_frame())draw_letters(dc,s,*foreground);
        if(actors.open && !actor_overlay.rgba.empty())draw_letters(dc,s,actor_overlay);
        if(!mystery_overlay.rgba.empty()){
            draw_letters(dc,s,mystery_overlay);
            const unsigned id=mystery::question_number(game->memory());
            if(id && language!=StoryLanguage::japanese){
                // Original questions occupy the 640x40 title band at 0xF0000 in
                // the six memory*.dat members. The title artwork remains visible.
                static constexpr const wchar_t* prompts[][2]{
                    {L"回想一下，昨天发生了什么？",L"Think back. What happened yesterday?"},
                    {L"正冈先生遇害时发生了什么？",L"What happened when Mr. Masaoka was killed?"},
                    {L"搜查这座宅子时发生了什么？",L"What happened during the search of the mansion?"},
                    {L"夏美遇害前后发生了什么？",L"What happened around the time Natsumi was killed?"},
                    {L"发现菱田婆婆遗体前后发生了什么？",L"What happened around the time Kiyo’s body was found?"},
                    {L"菱田婆婆的真实身份是……",L"Who was Kiyo, really?"}};
                const auto h=s.bottom-s.top;
                draw_ui_text(dc,{s.left,s.top+MulDiv(369,h,448),s.right,s.top+MulDiv(393,h,448)},
                             prompts[id-1][language==StoryLanguage::english],body,ivory,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
            }
        }
        if(l.rail.right>0)draw_rail(dc,l);
        else if(client.bottom-s.bottom>=19)
            draw_location(dc,{8,client.bottom-19,client.right-3,client.bottom-1},location_code(menu()));
        const auto system=menu();
        if(system.open && system.screen==3)draw_endings(dc,s);
        if(system.open && system.screen==2)draw_chapters(dc,s,system.subfocus);
        if(system.open && system.screen==1)draw_time_chart(dc,s);
        if(system.open && system.screen==4)draw_game_settings(dc,s,system);
        if(card_controls_open())draw_chapter_card(dc,s);
        const auto names=name_entry_view(game->memory(),game->runtime().manager);
        if(names.open)draw_name_entry(dc,s,names);else name_cells.clear();
    }
    std::optional<unsigned> actor_at(POINT p)const{
        if(!actors.open || !actors.accepting)return {};
        const auto s=view().screen;if(!PtInRect(&s,p))return {};
        const int x=MulDiv(p.x-s.left,640,s.right-s.left),y=MulDiv(p.y-s.top,448,s.bottom-s.top);
        if(y<88 || y>=344 || x<88 || x>=536)return {};
        return unsigned(x-88)/112;
    }
    std::optional<int> mystery_at(POINT p)const{
        const auto s=view().screen;
        if(!PtInRect(&s,p))return {};
        const int cell=mystery::option_at(game->memory(),MulDiv(p.x-s.left,640,s.right-s.left),
                                          MulDiv(p.y-s.top,448,s.bottom-s.top));
        return cell<0?std::nullopt:std::optional<int>(cell);
    }
    void draw_chapters(HDC dc,RECT stage,unsigned focus){
        const auto list=visible_chapter_list(game->memory());
        chart_cells.clear();fill(dc,stage,rail_color);
        const LONG w=stage.right-stage.left,h=stage.bottom-stage.top,pad=std::max(6L,w/22),left=stage.left+pad,right=stage.right-pad;
        const LONG top=stage.top+pad,step=std::clamp((h-100)/8,18L,56L);
        draw_ui_text(dc,{left,top,right,top+35},name(SystemMenuAction::Chapters).c_str(),title_font,ivory,DT_LEFT|DT_SINGLELINE);
        const auto table=program+"-chap";
        for(unsigned i=list.first;i<list.rows.size() && i<list.first+8;++i){
            const auto& row=list.rows[i];const LONG y=top+43+(i-list.first)*step;
            const RECT rc{left,y,right,y+step-3};fill(dc,rc,focus==i?RGB(36,42,52):RGB(22,30,41));
            if(focus==i)fill(dc,{left,y,left+3,rc.bottom},brass);
            const auto label=localize_chart_title(table,row.source_id,row.title_cp932,language);
            const auto number=std::to_wstring(row.number);
            const auto marker=std::wstring(system_string(0x238220));
            const auto heading=(language==StoryLanguage::english?marker+L" "+number:number+marker)+L"   "+wide(label);
            draw_ui_text(dc,{left+10,y,right-8,rc.bottom},heading.c_str(),step>=menu_height+4?menu_font:body,focus==i?brass:ivory,DT_LEFT|DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
            chart_cells.emplace_back(rc,i);
        }
    }
    void draw_game_settings(HDC dc,RECT stage,const SystemMenuView& state){
        fill(dc,stage,rail_color);chart_cells.clear();
        const LONG w=stage.right-stage.left,h=stage.bottom-stage.top,pad=std::max(8L,w/20),left=stage.left+pad,right=stage.right-pad;
        const LONG top=stage.top+pad,step=std::clamp(h/10,30L,66L);
        draw_ui_text(dc,{left,top,right,top+40},name(SystemMenuAction::Settings).c_str(),title_font,ivory,DT_LEFT|DT_SINGLELINE);
        if(state.settings_notice){
            const RECT confirm{left,top+64,right,top+64+step};
            draw_ui_text(dc,confirm,ui(L"自动保存已关闭。　○ 确认",L"Autosave is off.  ○ Confirm",L"オートセーブを解除しました。　○ 確認"),body,brass,DT_VCENTER|DT_SINGLELINE);
            chart_cells.emplace_back(confirm,0x10000);return;
        }
        const wchar_t* labels[]={ui(L"自动保存设置",L"Autosave",L"オートセーブ設定"),ui(L"自动保存提示",L"Autosave indicator",L"オートセーブ表示"),
            ui(L"声音输出",L"Audio output",L"音声出力"),ui(L"振动",L"Vibration",L"振動"),ui(L"应用设置并返回",L"Apply settings and return",L"設定を反映して戻る")};
        auto on=[&](bool b){return b?ui(L"开",L"On",L"入"):ui(L"关",L"Off",L"切");};
        for(unsigned i=0;i<5;++i){
            const LONG y=top+54+i*step;const RECT rc{left,y,right,y+step-4};
            fill(dc,rc,state.subfocus==i?RGB(36,42,52):RGB(22,30,41));
            if(state.subfocus==i)fill(dc,{left,y,left+3,rc.bottom},brass);
            draw_ui_text(dc,{left+11,y,right-8,rc.bottom},labels[i],menu_font,state.subfocus==i?brass:ivory,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
            std::wstring value;
            if(i==0)value=on(state.settings[0]);
            if(i==1)value=state.settings[1]?ui(L"显示",L"Show",L"表示"):ui(L"隐藏",L"Hide",L"非表示");
            if(i==2)value=state.settings[2]?ui(L"立体声",L"Stereo",L"ステレオ"):ui(L"单声道",L"Mono",L"モノラル");
            if(i==3)value=std::wstring(L"1P  ")+on(state.settings[3]<2)+L"     2P  "+on(!(state.settings[3]&1));
            draw_ui_text(dc,{left+11,y,right-10,rc.bottom},value.c_str(),menu_font,brass,DT_RIGHT|DT_SINGLELINE|DT_VCENTER);
            chart_cells.emplace_back(rc,i);
        }
    }
    const wchar_t* system_string(std::uint32_t address)const{
        for(const auto& r:system_strings)if(r.address==address){
            const auto raw=game->memory().bytes(address,r.bytes.size());
            if(!std::equal(raw.begin(),raw.end(),r.bytes.begin(),[](auto a,char b){return a==static_cast<unsigned char>(b);}))
                return L"";
            return ui(r.zh,r.en,r.ja);
        }
        return L"";
    }
    std::wstring confirm_name_text(const NameEntryView& entry)const{
        // 11C960 chooses the slot label, reads the original live name and draws the question.
        if(entry.slot>=2)return ui(L"提交这个答案？  ",L"Submit this answer?  ",L"この答えにしますか？  ")+wide(entry.draft_cp932,932);
        std::wstring result=system_string(entry.slot==0?0x205d90:0x205da0);
        const auto alias=language==StoryLanguage::english?english_default_player_name(entry.slot,entry.draft_cp932):std::string_view{};
        result+=alias.empty()?wide(entry.draft_cp932,932):wide(alias);
        if(language==StoryLanguage::japanese)result+=L"。";
        return result+system_string(0x205db8);
    }
    bool answer_word_reference(const NameEntryView& entry)const{
        if(!game || program!="sn4g" || !entry.open || entry.slot!=3)return false;
        const auto& m=game->memory();const auto script=m.read_u32(game->runtime().manager+0x38);
        const auto base=m.read_u32(script+4),cursor=m.read_u32(script+0xd8);
        // Original81 at SN4G selector21:F7D5F consumes its two branch labels
        // through F7D79 before opening this editor. The aid never chooses a
        // branch, changes a draft, or enumerates the original acceptance table.
        return m.read_u32(script+0xd0)==21 && cursor>=base && cursor-base==0xf7d79 &&
               m.read_u8(base+0xf7d5f)==0x81 && m.read_u8(base+0xf7d60)==0x18;
    }
    void draw_name_entry(HDC dc,RECT stage,const NameEntryView& entry){
        name_cells.clear();fill(dc,stage,rail_color);
        const LONG w=stage.right-stage.left,h=stage.bottom-stage.top,pad=std::max(4L,w/32);
        const LONG left=stage.left+pad,right=stage.right-pad,top=stage.top+pad;
        draw_ui_text(dc,{left,top,right,top+36},entry.slot>=2?ui(L"输入答案",L"Enter your answer",L"答えの入力"):
                     entry.slot==0?ui(L"男主角的名字",L"His name",L"男主人公の名前"):
                     ui(L"女主角的名字",L"Her name",L"女主人公の名前"),title_font,ivory,DT_LEFT|DT_SINGLELINE);
        const LONG slot_w=std::max(1L,std::min(36L,(right-left)/LONG(entry.max_chars)));
        const auto name=wide(entry.draft_cp932,932);
        for(unsigned i=0;i<entry.max_chars;++i){
            const LONG x=left+slot_w*i;fill(dc,{x,top+69,x+slot_w-3,top+70},slate);
            if(i<name.size())draw_ui_text(dc,{x,top+37,x+slot_w-3,top+68},std::wstring(1,name[i]).c_str(),title_font,brass,DT_CENTER|DT_SINGLELINE);
        }
        auto cell=[&](RECT rc,unsigned id,const std::wstring& text,bool focus){
            fill(dc,rc,focus?RGB(56,53,49):RGB(26,34,46));
            if(focus){auto brush=CreateSolidBrush(brass);FrameRect(dc,&rc,brush);DeleteObject(brush);}
            draw_ui_text(dc,rc,text.c_str(),body,focus?brass:ivory,DT_CENTER|DT_SINGLELINE|DT_VCENTER);
            name_cells.emplace_back(rc,id);
        };
        if(entry.confirming){
            draw_ui_text(dc,{left,top+82,right,top+118},confirm_name_text(entry).c_str(),body,ivory,DT_LEFT|DT_SINGLELINE);
            for(unsigned i=0;i<2;++i)cell({left+LONG(i)*116,top+124,left+LONG(i)*116+110,top+168},i,
                system_string(i?0x235ee0:0x235ed8),entry.confirm_focus==i);
            return;
        }
        const LONG grid=top+80,cw=std::max(1L,(right-left)/15),ch=std::max(1L,std::min(48L,(h-160)/9));
        for(const auto& item:entry.cells){
            const LONG x=left+cw*item.column,y=grid+ch*item.row;
            if(item.source_kind!=' ' && !item.text_cp932.empty())cell({x,y,x+cw-2,y+ch-2},item.index,wide(item.text_cp932,932),entry.focus==item.index);
        }
        const LONG y=std::min(stage.bottom-pad-38,grid+9*ch+10);
        if(entry.slot>=2 && y-grid>=7*ch+20){
            std::wstring help=ui(L"用平假名作答。鼠标点选，或用方向键选字、回车输入。I 键提交。",
                               L"Answer in hiragana. Click a character, or use the arrow keys and Enter. Press I to submit.",
                               L"ひらがなで入力。クリックまたは方向キーと Enter で選び、I キーで決定。");
            if(language!=StoryLanguage::japanese && answer_word_reference(entry))
                help=ui(L"日语输入参考：房间＝へや；钥匙＝かぎ；门＝どあ；窗户＝まど。",
                        L"Japanese hiragana input reference: room = へや; key = かぎ; door = どあ; window = まど.",L"");
            draw_ui_text(dc,{left,grid+6*ch+8,right,y-4},help.c_str(),small,slate,DT_LEFT|DT_WORDBREAK);
        }
        if(entry.slot>=2 && language!=StoryLanguage::japanese && entry.focus<entry.cells.size()){
            // These are reading aids for the mounted keyboard. Input and accepted
            // spellings still come from the original two-byte kana and answer tables.
            constexpr std::wstring_view kana=L"あいうえおかきくけこさしすせそたちつてとなにぬねのはひふへほまみむめもやゆよらりるれろわをんがぎぐげござじずぜぞだぢづでどばびぶべぼぱぴぷぺぽぁぃぅぇぉゃゅょっー";
            constexpr const wchar_t* readings[]={L"a",L"i",L"u",L"e",L"o",L"ka",L"ki",L"ku",L"ke",L"ko",
                L"sa",L"shi",L"su",L"se",L"so",L"ta",L"chi",L"tsu",L"te",L"to",L"na",L"ni",L"nu",L"ne",L"no",
                L"ha",L"hi",L"fu",L"he",L"ho",L"ma",L"mi",L"mu",L"me",L"mo",L"ya",L"yu",L"yo",
                L"ra",L"ri",L"ru",L"re",L"ro",L"wa",L"wo",L"n",L"ga",L"gi",L"gu",L"ge",L"go",
                L"za",L"ji",L"zu",L"ze",L"zo",L"da",L"ji",L"zu",L"de",L"do",L"ba",L"bi",L"bu",L"be",L"bo",
                L"pa",L"pi",L"pu",L"pe",L"po",L"a",L"i",L"u",L"e",L"o",L"ya",L"yu",L"yo",L"っ",L"ー"};
            static_assert(kana.size()==std::size(readings));
            const auto key=wide(entry.cells[entry.focus].text_cp932,932);
            const auto index=key.size()==1?kana.find(key.front()):std::wstring_view::npos;
            if(index!=std::wstring_view::npos){
                const auto hint=key+L"   "+readings[index];
                draw_ui_text(dc,{left,y,right,y+36},hint.c_str(),small,brass,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
            }
        }
        const auto width=std::max(1L,(right-left)/4);
        const wchar_t* actions[]={ui(L"上一组",L"Previous group",L"前の組"),ui(L"下一组",L"Next group",L"次の組"),
            ui(L"删除  ×",L"Delete  ×",L"削除  ×"),ui(L"决定  △",L"Done  △",L"決定  △")};
        for(unsigned i=entry.slot>=2?2:0;i<4;++i)cell({left+LONG(i)*width,y,left+LONG(i+1)*width-2,y+36},0x10000+i,actions[i],false);
    }
    std::optional<unsigned> name_at(POINT pt){
        if(!name_entry_view(game->memory(),game->runtime().manager).open)return {};
        UpdateWindow(window);for(const auto& [rect,id]:name_cells)if(PtInRect(&rect,pt))return id;return {};
    }
    void draw_endings(HDC dc,RECT stage){
        const auto entries=ending_list_entries(game->memory());
        const auto focus=menu().subfocus;
        chart_cells.clear();
        fill(dc,stage,rail_color);
        const LONG w=stage.right-stage.left,h=stage.bottom-stage.top,margin=std::max(6L,w/24);
        const LONG left=stage.left+margin,top=stage.top+margin;
        draw_ui_text(dc,{left,top,stage.right-margin,top+36},name(SystemMenuAction::Endings).c_str(),
                     title_font,ivory,DT_LEFT|DT_SINGLELINE|DT_END_ELLIPSIS);
        const unsigned rows=unsigned((entries.size()+9)/10);
        if(!rows)return;
        const LONG cell_w=(w-2*margin)/10,cell_h=std::min(53L,(h-2*margin-70)/LONG(rows));
        for(unsigned i=0;i<entries.size();++i){
            const RECT cell{left+LONG(i%10)*cell_w,top+48+LONG(i/10)*cell_h,left+LONG(i%10+1)*cell_w-3,top+48+LONG(i/10+1)*cell_h-3};
            chart_cells.emplace_back(cell,i);
            const bool available=entries[i].reached || entries[i].replay_prompt;
            fill(dc,cell,available?RGB(62,57,47):RGB(27,34,45));
            if(i==focus){const auto pen=CreateSolidBrush(brass);FrameRect(dc,&cell,pen);DeleteObject(pen);}
            draw_ui_text(dc,cell,std::to_wstring(i+1).c_str(),small,available?brass:slate,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
        if(focus<entries.size() && (entries[focus].reached || entries[focus].replay_prompt)){
            // 1ABE20 selects the prompt at 229738 instead of revealing the title.
            const std::wstring text=entries[focus].replay_prompt?
                system_string(0x229738):
                wide(localize_chart_title(program+"-end",focus,entries[focus].title_cp932,language));
            const LONG y=top+48+rows*cell_h+4;
            draw_ui_text(dc,{left,y,stage.right-margin,stage.bottom},text.c_str(),body,ivory,DT_LEFT|DT_WORDBREAK);
        }
    }
    void draw_time_chart(HDC dc,RECT stage){
        const auto view=visible_time_chart(game->memory());
        chart_cells.clear();fill(dc,stage,rail_color);
        const LONG w=stage.right-stage.left,h=stage.bottom-stage.top,pad=std::max(4L,w/40);
        const LONG left=stage.left+pad,top=stage.top+pad,label=std::max(42L,w/9),cw=(w-pad*2-label)/4;
        draw_ui_text(dc,{left,top,stage.right-pad,top+32},name(SystemMenuAction::Timeline).c_str(),title_font,ivory,DT_LEFT|DT_SINGLELINE);
        const LONG grid=top+38,rows_top=grid+30,ch=std::clamp((h-116)/12,16L,53L);
        draw_ui_text(dc,{left,grid,left+label,rows_top},ui(L"时间",L"Time",L"時間"),body,brass,DT_VCENTER|DT_SINGLELINE);
        for(unsigned a=0;a<4;++a){
            const LONG x=left+label+cw*a;
            const auto heading=localize_chart_title("sn4g-head",a+2,view.actors_cp932[a],language);
            draw_ui_text(dc,{x,grid,x+cw,rows_top},wide(heading).c_str(),body,brass,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
        for(unsigned i=view.first_row;i<view.times.size() && i<view.first_row+12;++i){
            const LONG y=rows_top+(i-view.first_row)*ch;
            const auto [hour,minute]=view.times[i];std::wostringstream time;
            if(hour<0)time<<ui(L"序章",L"Prologue",L"序章");
            else time<<std::setw(2)<<std::setfill(L'0')<<hour<<L":"<<std::setw(2)<<minute;
            draw_ui_text(dc,{left,y,left+label,y+ch},time.str().c_str(),small,slate,DT_LEFT|DT_SINGLELINE|DT_VCENTER);
            for(unsigned a=0;a<4;++a){
                const LONG x=left+label+cw*a;const RECT cell{x,y,x+cw-2,y+ch-2};
                const auto slot=std::find_if(view.available_cells.begin(),view.available_cells.end(),
                    [&](const TimeChartCell& e){return e.time_row==i && e.actor==a;});
                const bool open=slot!=view.available_cells.end();
                fill(dc,cell,open?RGB(34,42,53):RGB(23,29,39));
                if(i==view.row && a==view.actor){const auto brush=CreateSolidBrush(brass);FrameRect(dc,&cell,brush);DeleteObject(brush);}
                if(!open)continue;
                const auto caption=localize_chart_title("sn4g-time",slot->title_id,slot->title_cp932,language);
                draw_ui_text(dc,{x+3,y,x+cw-5,y+ch-2},wide(caption).c_str(),small,ivory,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
                chart_cells.emplace_back(cell,i*4+a);
            }
        }
        const auto current=std::find_if(view.available_cells.begin(),view.available_cells.end(),
            [&](const TimeChartCell& e){return e.time_row==view.row && e.actor==view.actor;});
        if(current!=view.available_cells.end()){
            const auto text=localize_chart_title("sn4g-time",current->title_id,current->title_cp932,language);
            draw_ui_text(dc,{left,rows_top+12*ch+6,stage.right-pad,stage.bottom},wide(text).c_str(),body,ivory,DT_LEFT|DT_WORDBREAK);
        }
    }
    void draw_chapter_card(HDC dc,RECT stage){
        const auto& m=game->memory();
        const auto id=m.read_u32(0x238940),state=m.read_u32(0x2380d0);
        const LONG w=stage.right-stage.left,h=stage.bottom-stage.top,margin=std::max(8L,w/16);
        fill(dc,stage,rail_color);
        chart_cells.clear();
        draw_ui_text(dc,{stage.left+margin,stage.top+h/20,stage.right-margin,stage.top+h/6},
            chapter_open()?ui(L"章末存档",L"Chapter save",L"章末セーブ"):ui(L"记忆卡",L"Memory card",L"メモリーカード"),title_font,brass,DT_LEFT|DT_VCENTER|DT_SINGLELINE);
        if(chapter_message_id!=id){
            chapter_message=chapter_art.message(root,m,id);chapter_message_id=id;
        }
        if(!chapter_message.rgba.empty())draw_letters(dc,stage,chapter_message);
        const wchar_t* hint=nullptr;
        switch(id){
        case 14:hint=ui(L"选择用来保存进度的记忆卡。",L"Choose the memory card to save to.",L"");break;
        case 19:hint=ui(L"选择存档位置。",L"Choose a save slot.",L"");break;
        case 20:hint=ui(L"覆盖这个存档吗？",L"Overwrite this save?",L"");break;
        case 26:hint=ui(L"正在保存……",L"Saving…",L"");break;
        case 27:hint=ui(L"存档完成。",L"Save complete.",L"");break;
        case 28:hint=ui(L"存档失败。",L"Save failed.",L"");break;
        case 34:hint=ui(L"保存到目前为止的游戏进度吗？",L"Save your progress so far?",L"");break;
        case 35:hint=ui(L"进度不会保存。要继续吗？",L"Continue without saving your progress?",L"");break;
        case 36:hint=ui(L"确定结束游戏吗？",L"Are you sure you want to quit the game?",L"");break;
        case 39:hint=ui(L"游戏进度不会保存。仍要退出吗？",L"Your progress won't be saved. Is that OK?",L"");break;
        }
        if(hint && *hint)draw_ui_text(dc,{stage.left+margin,stage.top+h/2,stage.right-margin,stage.top+h*61/100},
            hint,body,ivory,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
        LONG top=stage.top+h*64/100;
        auto cell=[&](unsigned key,unsigned col,unsigned cols,const std::wstring& label,bool focused){
            const LONG width=(w-2*margin)/LONG(cols);
            RECT rect{stage.left+margin+LONG(col)*width,top,stage.left+margin+LONG(col+1)*width-4,top+std::max(32L,h/10)};
            fill(dc,rect,focused?RGB(76,64,48):RGB(32,39,49));
            if(focused){auto pen=CreateSolidBrush(brass);FrameRect(dc,&rect,pen);DeleteObject(pen);}
            draw_ui_text(dc,rect,label.c_str(),body,focused?ivory:slate,DT_CENTER|DT_VCENTER|DT_SINGLELINE|DT_END_ELLIPSIS);
            chart_cells.emplace_back(rect,0x20000+key);
        };
        if(m.read_u32(0x23805c)){
            const auto focus=m.read_u32(0x238058);
            cell(1,0,2,ui(L"是",L"Yes",L"はい"),focus==1);cell(0,1,2,ui(L"否",L"No",L"いいえ"),focus==0);
        }else if(state==0x20 || (m.read_u32(0x2388e8)==12 && state==7)){
            for(unsigned i=0;i<2;++i){
                std::wstring label=ui(L"接口 ",L"Port ",L"差込口 ");label+=std::to_wstring(i+1);
                if(m.read_u32(0x23a000+36*i)==2)label+=ui(L" · 未插卡",L" · empty",L" · 未挿入");
                cell(0x100+i,i,2,label,m.read_u32(0x2380a0)==i);
            }
        }else if(m.read_u32(0x238150) && !m.read_u32(0x23815c) && (state==0x22 || state==0x10)){
            const auto total=std::min(3u,m.read_u32(0x238184));
            for(unsigned i=0;i<total;++i){
                const auto p=m.read_u32(0x1e4bcf8+4*i);
                std::wstring label=m.read_u32(p+44)?ui(L"存档 ",L"Save ",L"セーブ "):ui(L"新存档 ",L"New save ",L"新規 ");
                label+=std::to_wstring(1+(m.read_u32(p+44)?m.read_u32(p):m.read_u32(0x238168)));
                cell(0x200+i,i,total,label,i==m.read_u32(0x238170));
            }
            top+=std::max(32L,h/10)+5;
            if(m.read_u32(0x238184)>3){
                cell(0x300,0,3,ui(L"上一个",L"Previous",L"前へ"),false);
                cell(0x301,1,3,ui(L"下一个",L"Next",L"次へ"),false);
            }
            cell(0x401,2,3,ui(L"返回",L"Back",L"戻る"),false);
        }else if(state==0x25 || state==0x18 || state==0x29 || state==0x2a || state==0x2b ||
                 (m.read_u32(0x2388e8)==12 && (state==0x15 || state==0x16 || state==0x17 || state==0x1f || state==0x31)))
            cell(0x400,0,1,ui(L"确认",L"Confirm",L"決定"),true);
    }
    std::optional<unsigned> chart_at(POINT pt){
        const auto state=menu();if(!card_controls_open() && (!state.open || state.screen<1 || state.screen>4))return {};
        UpdateWindow(window);
        for(const auto& [cell,id]:chart_cells)if(PtInRect(&cell,pt))return id;
        return {};
    }
    void draw_letters(HDC dc,RECT stage,const RasterFrame& letters){
        BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=LONG(letters.width);
        info.bmiHeader.biHeight=-LONG(letters.height);info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;
        void* memory=nullptr;const auto bmp=CreateDIBSection(dc,&info,DIB_RGB_COLORS,&memory,nullptr,0);
        if(!bmp)return;
        const auto memdc=CreateCompatibleDC(dc);if(!memdc){DeleteObject(bmp);return;}
        const auto old=SelectObject(memdc,bmp);auto* dst=static_cast<u32*>(memory);
        for(size_t i=0;i<letters.rgba.size()/4;++i){const auto* p=&letters.rgba[i*4];
            const unsigned a=p[3];dst[i]=(a<<24)|(p[0]*a/255<<16)|(p[1]*a/255<<8)|(p[2]*a/255);}
        AlphaBlend(dc,stage.left,stage.top,stage.right-stage.left,stage.bottom-stage.top,memdc,0,0,
                   letters.width,letters.height,{AC_SRC_OVER,0,255,AC_SRC_ALPHA});
        SelectObject(memdc,old);DeleteDC(memdc);DeleteObject(bmp);
    }
    void draw_controls(HDC dc,int width,int height){
        const int top=height>=460?height/10+90:height/5;
        draw_ui_text(dc,{8,top,width-8,top+28},system_string(0x20737d),body,brass,DT_CENTER|DT_SINGLELINE);
        const int row_height=std::clamp((height-top-110)/7,26,64);
        constexpr u32 addresses[]={0x2072f8,0x20730d,0x20731a,0x207329,0x20733a,0x207357,0x207364};
        const wchar_t* keys[]={L"I",L"Enter",L"↑ ↓",L"↑",L"↓",L"End",L"← →"};
        for(unsigned i=0;i<std::size(addresses);++i){
            const auto* label=system_string(addresses[i]);
            while(*label==L'：' || *label==L':' || *label==L' ' || *label==L'—')++label;
            int y=top+30+int(i)*row_height;
            draw_ui_text(dc,{12,y,width-9,y+16},keys[i],small,brass,DT_SINGLELINE);
            RECT box{12,y+15,width-7,y+row_height},measure=box;
            const auto old=SelectObject(dc,menu_font);
            DrawTextW(dc,label,-1,&measure,DT_CALCRECT|DT_WORDBREAK|DT_NOPREFIX);
            SelectObject(dc,old);
            const auto font=measure.bottom-measure.top<=box.bottom-box.top?menu_font:body;
            draw_ui_text(dc,box,label,font,ivory,DT_WORDBREAK|DT_END_ELLIPSIS);
        }
    }
    std::array<std::wstring,2> brightness_instructions()const{
        std::array<std::wstring,2> lines;
        constexpr u32 labels[2][3]={{0x20726d,0x207280,0x20728f},{0x2072a2,0x2072b5,0x2072c6}};
        for(unsigned i=0;i<2;++i)for(auto addr:labels[i]){
            if(!lines[i].empty() && language==StoryLanguage::english)lines[i]+=L' ';
            lines[i]+=system_string(addr);
        }
        return lines;
    }
    void draw_rail_title(HDC dc,int w,int h){
        const int cx=w/2,cy=h/10;
        const auto moon=CreateSolidBrush(brass);const auto old=SelectObject(dc,moon);
        const auto oldpen=SelectObject(dc,GetStockObject(NULL_PEN));
        Ellipse(dc,cx-19,cy-19,cx+19,cy+19);
        const auto shade=CreateSolidBrush(rail_color);SelectObject(dc,shade);
        Ellipse(dc,cx-11,cy-22,cx+22,cy+14);SelectObject(dc,old);SelectObject(dc,oldpen);DeleteObject(shade);DeleteObject(moon);
        if(h>=460)draw_ui_text(dc,{3,cy+27,w-3,cy+61},ui(L"镰鼬之夜",L"Kamaitachi",L"かまいたちの夜"),title_font,ivory,DT_CENTER|DT_SINGLELINE);
        const auto edition=program=="sn2"?ui(L"舒普尔旅馆  /  ×3",L"Spur Lodge  /  ×3",L"シュプール  /  ×3"):
            program=="sn4"?ui(L"监狱岛  /  ×3",L"Prison Island  /  ×3",L"監獄島  /  ×3"):ui(L"三日月岛  /  ×3",L"Mikazuki  /  ×3",L"三日月島  /  ×3");
        if(h>=460)draw_ui_text(dc,{3,cy+65,w-3,cy+85},edition,small,brass,DT_CENTER|DT_SINGLELINE);
    }
    void draw_rail(HDC dc,const Layout& l){
        const int w=l.rail.right,h=l.rail.bottom;
        fill(dc,l.rail,rail_color);
        fill(dc,{w-1,0,w,h},RGB(104,85,63));
        const auto system=menu();
        const bool brightness=!system.open && system.brightness_visible;
        if(brightness || system.interval_level){
            const auto endpoints=brightness?
                std::wstring(system_string(0x2072de))+L"   "+std::to_wstring(system.brightness_level)+L"%   "+system_string(0x2072d7):
                std::wstring(system_string(0x2378f0))+L"    ·    "+system_string(0x2378f8);
            draw_ui_text(dc,{6,8,w-6,35},endpoints.c_str(),body,brass,DT_CENTER|DT_SINGLELINE);
            if(h>=460){
                std::wstring description;
                if(brightness){
                    const auto info=brightness_instructions();
                    description=info[0]+L"\n"+info[1];
                }else description=std::wstring(system_string(0x20d640))+L"○"+system_string(0x20d660);
                draw_ui_text(dc,{12,40,w-10,h*32/100-4},description.c_str(),body,ivory,DT_WORDBREAK|DT_END_ELLIPSIS);
            }
        }else draw_rail_title(dc,w,h);
        if(!system.open && system.controls_visible)draw_controls(dc,w,h);
        for(const auto& row:rail_rows(l)){
            const auto color=row.enabled?(row.selected?brass:ivory):RGB(114,123,136);
            if(row.selected){fill(dc,{0,row.rect.top,2,row.rect.bottom},brass);fill(dc,{2,row.rect.top,w-1,row.rect.bottom},RGB(26,33,44));}
            const auto pen=CreatePen(PS_SOLID,1,color);const auto prev=SelectObject(dc,pen);
            const auto plain=SelectObject(dc,GetStockObject(HOLLOW_BRUSH));
            const int x=14,y=(row.rect.top+row.rect.bottom)/2;
            int i=row.command==RailCommand::display?2:row.command==RailCommand::save_slot?3:
                row.command==RailCommand::back?1:0;
            if(row.command==RailCommand::source && system.screen==0 && row.value<system.actions.size()){
                switch(system.actions[row.value]){
                case SystemMenuAction::Endings:i=4;break;
                case SystemMenuAction::Settings:i=2;break;
                case SystemMenuAction::Memory:case SystemMenuAction::SaveAndQuit:i=3;break;
                case SystemMenuAction::Chapters:i=5;break;
                case SystemMenuAction::Timeline:i=0;break;
                }
            }
            if(i==0){line(dc,x+8,y-7,x+8,y);line(dc,x,y,x+16,y);line(dc,x,y,x,y+6);line(dc,x+16,y,x+16,y+6);}
            if(i==1){line(dc,x,y-8,x,y+8);line(dc,x,y-7,x+14,y-5);line(dc,x+14,y-5,x+9,y+1);line(dc,x+9,y+1,x,y-1);}
            if(i==2){line(dc,x,y-4,x+17,y-4);line(dc,x,y+4,x+17,y+4);Ellipse(dc,x+4,y-7,x+10,y-1);Ellipse(dc,x+9,y+1,x+15,y+7);}
            if(i==3){Rectangle(dc,x,y-8,x+14,y+9);line(dc,x+9,y,x+11,y);}
            if(i==4){for(int j=0;j<4;++j){const int xx=x+(j%2)*9,yy=y-7+(j/2)*9;Rectangle(dc,xx,yy,xx+6,yy+6);}}
            if(i==5){for(int j=0;j<3;++j){const int yy=y-6+j*6;Rectangle(dc,x,yy,x+3,yy+3);line(dc,x+6,yy+1,x+16,yy+1);}}
            SelectObject(dc,plain);SelectObject(dc,prev);DeleteObject(pen);
            RECT label{w<160?33:38,row.rect.top,w-3,row.rect.bottom};
            RECT measured=label;
            auto label_font=menu_font;
            const auto oldfont=SelectObject(dc,label_font);
            DrawTextW(dc,row.label.c_str(),-1,&measured,DT_NOPREFIX|DT_WORDBREAK|DT_CALCRECT);
            if(measured.bottom-measured.top>label.bottom-label.top){
                label_font=body;SelectObject(dc,label_font);measured=label;
                DrawTextW(dc,row.label.c_str(),-1,&measured,DT_NOPREFIX|DT_WORDBREAK|DT_CALCRECT);
            }
            SelectObject(dc,oldfont);
            const LONG label_height=measured.bottom-measured.top;
            label.top+=std::max(0L,(label.bottom-label.top-label_height)/2);
            draw_ui_text(dc,label,row.label.c_str(),label_font,color,DT_LEFT|DT_WORDBREAK|DT_END_ELLIPSIS);
        }
        const wchar_t* languages[]={L"日本語 · F6",chinese_text_reviewed?L"简体中文 · F6":L"简中校对稿 · F6",L"English draft · F6"};
        auto state=frontier.empty()?ui(L"原盘运行中",L"Original scenario",L"原作進行中"):
            ui(L"移植断点",L"Porting frontier",L"移植の到達点");
        auto detail=frontier.empty()?std::wstring(languages[unsigned(language)]):frontier_address(frontier);
        const bool confirm=frontier.empty() && !system.open && alternate_label_armed(game->memory(),game->runtime().manager);
        if(confirm){
            state=ui(L"○ 继续",L"○ Continue",L"○ 次へ");
            detail=ui(L"回车／点击画面",L"Enter / click",L"Enter／クリック");
        }
        draw_ui_text(dc,{12,h-90,w-9,h-69},state,small,confirm || !frontier.empty()?brass:slate,DT_SINGLELINE);
        draw_ui_text(dc,{12,h-66,w-9,h-40},detail.c_str(),small,slate,DT_SINGLELINE|DT_END_ELLIPSIS);
        if(!feedback.empty())draw_ui_text(dc,{12,h-39,w-9,h-19},feedback.c_str(),small,brass,DT_SINGLELINE|DT_END_ELLIPSIS);
        draw_location(dc,{8,h-19,w-3,h-1},location_code(system));
    }
    void draw_location(HDC dc,RECT rect,const std::wstring& code)const{
        if(code.empty())return;
        const auto previous=SelectObject(dc,locator_font);
        SIZE size{};GetTextExtentPoint32W(dc,code.c_str(),int(code.size()),&size);
        SelectObject(dc,previous);
        HFONT fitted=nullptr;
        if(size.cx>rect.right-rect.left){
            const int height=std::clamp(menu_height/2,11,15);
            fitted=create_ui_font(std::max(1,MulDiv(height,rect.right-rect.left,size.cx)),FW_NORMAL,L"Consolas");
        }
        draw_ui_text(dc,rect,code.c_str(),fitted?fitted:locator_font,RGB(106,120,139),DT_LEFT|DT_SINGLELINE|DT_VCENTER);
        if(fitted)DeleteObject(fitted);
    }
    std::wstring location_code(const SystemMenuView& system)const{
        const auto& memory=game->memory();
        const u32 script=memory.read_u32(game->runtime().manager+0x38);
        if(!script || script>GuestMemory::size-0xdc)return {};
        const u32 base=memory.read_u32(script+4),cursor=memory.read_u32(script+0xd8);
        if(!base || cursor<base || cursor>=GuestMemory::size)return {};
        std::wstring code=program=="sn2"?L"11":program=="sn4"?L"12":L"13";
        code+=L"-"+base36(memory.read_u32(script+0xd0))+L"-"+base36(memory.read_u32(script+0xd4))+L"-"+base36(cursor-base);
        if(system.open)code+=L"-"+base36(system.screen)+L"-"+base36(system.focus)+L"-"+base36(system.subfocus);
        return code;
    }
};

LRESULT CALLBACK messages(HWND wnd,UINT msg,WPARAM wp,LPARAM lp){
    if(msg==WM_NCCREATE){
        auto* p=static_cast<Player*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        p->window=wnd;SetWindowLongPtrW(wnd,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(p));
    }
    auto* p=reinterpret_cast<Player*>(GetWindowLongPtrW(wnd,GWLP_USERDATA));
    if(!p)return DefWindowProcW(wnd,msg,wp,lp);
    try{
        switch(msg){
        case WM_CREATE:return 0;
        case WM_GETMINMAXINFO:reinterpret_cast<MINMAXINFO*>(lp)->ptMinTrackSize={400,320};return 0;
        case WM_ERASEBKGND:return 1;
        case WM_PAINT:{
            p->timing("paint_begin");
            PAINTSTRUCT ps{};
            const auto target=BeginPaint(wnd,&ps);
            HPAINTBUFFER buffer=nullptr;
            try{
                if(!IsRectEmpty(&ps.rcPaint)){
                    RECT client{};GetClientRect(wnd,&client);
                    HDC frame=nullptr;
                    buffer=BeginBufferedPaint(target,&client,BPBF_COMPATIBLEBITMAP,nullptr,&frame);
                    require(buffer && frame,"Could not allocate the window frame buffer");
                    p->paint(frame);
                }
            }catch(...){
                if(buffer)EndBufferedPaint(buffer,FALSE);
                EndPaint(wnd,&ps);throw;
            }
            const HRESULT result=buffer?EndBufferedPaint(buffer,TRUE):S_OK;
            EndPaint(wnd,&ps);
            require(SUCCEEDED(result),"Could not present the finished window frame");
            if(buffer)p->timing("paint_end");
            return 0;
        }
        case WM_PRINTCLIENT:p->paint(reinterpret_cast<HDC>(wp));return 0;
        case WM_TIMER:
            if(wp==overwrite_timer && p->verify && p->modal_reply){
                const auto dlg=GetLastActivePopup(wnd);
                if(dlg!=wnd && GetWindow(dlg,GW_OWNER)==wnd){
                    const auto button=GetDlgItem(dlg,p->modal_reply);
                    if(button){++p->modal_clicked;p->modal_reply=0;PostMessageW(button,BM_CLICK,0,0);}
                }
            }
            return 0;
        case WM_COMMAND:
            if(LOWORD(wp)>=continue_slot_message && LOWORD(wp)<continue_slot_message+pc_slots && !p->menu().open && p->has_progress)
                p->load_slot(LOWORD(wp)-continue_slot_message);
            return 0;
        case WM_SIZE:p->next=Clock::now()+cycle;InvalidateRect(wnd,nullptr,FALSE);return 0;
        case WM_KILLFOCUS:p->clear_keys();p->display_key_release.fill(false);p->display_press.reset();return 0;
        case title_pad_msg:p->poll_title_pad();return 0;
        case WM_KEYDOWN:{
            if(wp>=256 || p->keys[wp] || p->display_key_release[wp])return 0;
            p->keys[wp]=true;
            if(p->display_page){p->display_key(unsigned(wp));return 0;}
            if(wp==VK_F11 || (wp==VK_ESCAPE && p->fullscreen))p->setting(3);
            else if(wp==VK_F2)p->setting(1);
            else if(wp==VK_F3)p->setting(2);
            else if(wp==VK_F4)p->setting(8);
            else if(wp==VK_F12)p->capture_screenshot();
            else if(wp==VK_F1)p->settings();
            else if(wp==VK_F6)p->change_language(static_cast<StoryLanguage>((unsigned(p->language)+1)%3));
            else if(p->lobby!=Lobby::hidden)p->lobby_key(unsigned(wp));
            else if(p->failed_save_input && (wp==VK_F5 || wp==VK_RETURN))p->retry_save();
            else if(wp==VK_F9 && !p->menu().open)p->continue_game();
            else if(wp==VK_TAB && p->menu().open && (p->menu().screen==14 || p->menu().screen==12) && !p->use_original_card){
                p->use_original_card=true;p->clear_keys();InvalidateRect(wnd,nullptr,FALSE);
            }
            else if(!p->use_original_card && p->menu().open && (p->menu().screen==14 || p->menu().screen==12) && (wp==VK_UP || wp==VK_DOWN)){
                p->selected_slot=(p->selected_slot+(wp==VK_UP?pc_slots-1:1))%pc_slots;InvalidateRect(wnd,nullptr,FALSE);
            }
            else if(!p->use_original_card && p->menu().open && (p->menu().screen==14 || p->menu().screen==12) && (wp==VK_F5 || wp==VK_RETURN || wp==VK_SPACE || wp=='L'))p->save_slot(p->selected_slot);
            else if(wp==VK_ESCAPE && p->menu().open)p->pressed|=0x4000;
            else p->pressed|=physical_key(unsigned(wp));
            return 0;
        }
        case WM_KEYUP:if(wp<256){p->keys[wp]=false;p->display_key_release[wp]=false;}if(!p->display_page)p->poll_title_pad();return 0;
        case WM_MOUSEWHEEL:
            if(p->display_page && p->display_about){p->scroll_about(-GET_WHEEL_DELTA_WPARAM(wp)/WHEEL_DELTA*48);return 0;}
            break;
        case WM_MOUSEMOVE:{
            const POINT pt{GET_X_LPARAM(lp),GET_Y_LPARAM(lp)};
            if(p->display_page){if(auto i=p->display_at(pt)){p->display_focus=*i;InvalidateRect(wnd,nullptr,FALSE);}return 0;}
            if(p->lobby!=Lobby::hidden){if(auto i=p->lobby_at(pt)){p->lobby_focus=*i;InvalidateRect(wnd,nullptr,FALSE);}return 0;}
            if(p->actors.open){if(auto i=p->actor_at(pt))p->actor_hover=i;return 0;}
            if(auto id=p->name_at(pt)){if(*id<0x10000)p->name_hover=id;return 0;}
            if(const auto hit=p->chart_at(pt)){if(!p->card_controls_open())p->menu_hover=hit;return 0;}
            if(auto row=p->rail_at(pt)){
                const auto items=p->rail_rows(p->view());if(items[*row].command==RailCommand::source)p->menu_hover=items[*row].value;
            }
            if(!p->frontier.empty() || p->menu().open)return 0;
            auto hit=p->option(pt);
            if(hit)p->pending_choice=hit;
            return 0;
        }
        case WM_LBUTTONDOWN:{
            POINT pt{GET_X_LPARAM(lp),GET_Y_LPARAM(lp)};const auto v=p->view();SetFocus(wnd);
            if(p->display_page){p->display_press=p->display_at(pt);if(p->display_press)SetCapture(wnd);return 0;}
            if(p->lobby!=Lobby::hidden){p->lobby_press=p->lobby_at(pt);if(p->lobby_press)SetCapture(wnd);return 0;}
            if(p->actors.open && PtInRect(&v.screen,pt)){p->actor_press=p->actor_at(pt);if(p->actor_press)SetCapture(wnd);return 0;}
            if(mystery::active(p->game->memory()) && PtInRect(&v.screen,pt)){
                p->mystery_press=p->mystery_at(pt);if(p->mystery_press)SetCapture(wnd);return 0;
            }
            if(const auto id=p->name_at(pt)){p->name_press=id;SetCapture(wnd);return 0;}
            if(name_entry_view(p->game->memory(),p->game->runtime().manager).open && PtInRect(&v.screen,pt))return 0;
            if(const auto hit=p->chart_at(pt)){p->chart_press=hit;SetCapture(wnd);return 0;}
            if(auto row=p->rail_at(pt)){p->rail_press=row;SetCapture(wnd);return 0;}
            if(p->frontier.empty() && !p->menu().open && PtInRect(&v.screen,pt)){
                p->pressed_stage=true;p->pressed_choice=p->option(pt);SetCapture(wnd);
            }
            return 0;
        }
        case WM_LBUTTONUP:{
            POINT pt{GET_X_LPARAM(lp),GET_Y_LPARAM(lp)};
            if(p->display_page){const auto down=p->display_press;p->display_press.reset();if(GetCapture()==wnd)ReleaseCapture();if(down && p->display_at(pt)==down)p->display_activate(*down);return 0;}
            if(p->lobby!=Lobby::hidden){
                const auto down=p->lobby_press;p->lobby_press.reset();if(GetCapture()==wnd)ReleaseCapture();
                if(down && p->lobby_at(pt)==down){p->lobby_focus=*down;p->lobby_key(VK_RETURN);p->poll_title_pad();}return 0;
            }
            if(p->actor_press){
                const auto hit=p->actor_press;p->actor_press.reset();if(GetCapture()==wnd)ReleaseCapture();
                if(p->actor_at(pt)==hit){p->actor_hover=hit;p->actor_click=true;}return 0;
            }
            if(p->mystery_press){
                const auto hit=p->mystery_press;p->mystery_press.reset();if(GetCapture()==wnd)ReleaseCapture();
                if(p->mystery_at(pt)==hit){p->mystery_target=hit;p->mystery_source=p->game->memory().read_u32(mystery::descriptor);}
                return 0;
            }
            if(p->name_press){
                const auto id=p->name_press;p->name_press.reset();if(GetCapture()==wnd)ReleaseCapture();
                if(p->name_at(pt)==id){
                    if(*id<0x10000){p->name_hover=id;p->name_click=true;}
                    else{constexpr std::array<unsigned,4> masks{0x400,0x800,0x4000,0x1000};p->pressed|=masks.at(*id-0x10000);}
                }
                return 0;
            }
            if(p->chart_press){
                const auto last=p->chart_press;p->chart_press.reset();if(GetCapture()==wnd)ReleaseCapture();
                if(p->chart_at(pt)==last){
                    if(p->card_controls_open() && *last>=0x20000)
                        p->chapter_click=Player::CardClick{p->game->memory().read_u32(0x2380d0),*last-0x20000};
                    else if(*last==0x10000)p->pressed|=0x2000;
                    else{p->menu_hover=last;p->menu_click=true;}
                }return 0;
            }
            if(p->rail_press){
                const auto last=p->rail_press;p->rail_press.reset();if(GetCapture()==wnd)ReleaseCapture();
                if(p->rail_at(pt)==last)p->rail_action(*last);return 0;
            }
            auto hit=p->option(pt);const auto v=p->view();
            if(p->pressed_stage && PtInRect(&v.screen,pt) && hit==p->pressed_choice && p->frontier.empty()){
                if(hit){p->pending_choice=hit;p->choice_confirm=true;}
                else{
                    const auto& m=p->game->memory();const auto ctx=m.read_u32(p->game->runtime().manager+0x40);
                    if(m.read_u32(m.read_u32(ctx))!=0x11e748)p->pressed|=0x2000;
                }
            }
            p->pressed_stage=false;p->pressed_choice.reset();if(GetCapture()==wnd)ReleaseCapture();return 0;
        }
        case WM_CAPTURECHANGED:p->display_press.reset();p->pressed_stage=false;p->pressed_choice.reset();p->rail_press.reset();p->chart_press.reset();p->name_press.reset();p->lobby_press.reset();p->actor_press.reset();p->mystery_press.reset();return 0;
        case WM_CLOSE:DestroyWindow(wnd);return 0;
        case WM_DESTROY:PostQuitMessage(p->failed?2:0);return 0;
        }
    }catch(const std::exception& e){
        p->frontier=e.what();p->refresh_caption();
        if(p->verify){p->failed=true;std::ofstream(p->report_path())
            <<"{\"status\":\"failed\",\"error\":"<<std::quoted(p->frontier)<<"}";PostMessageW(wnd,WM_CLOSE,0,0);}
        return 0;
    }
    return DefWindowProcW(wnd,msg,wp,lp);
}
std::filesystem::path last_disc(const std::filesystem::path& project){
    std::ifstream file(project/"local/pc-core/player/last-disc.txt",std::ios::binary|std::ios::ate);
    const auto length=file.tellg();
    if(length<=0 || length>4*32767)return {};
    std::string bytes(static_cast<std::size_t>(length),'\0');
    if(!file.seekg(0) || !file.read(bytes.data(),length) || bytes.find('\0')!=std::string::npos)return {};
    try{
        std::filesystem::path path=wide(bytes);
        if(path.is_absolute())return path;
    }catch(const std::runtime_error&){}
    return {};
}
void remember_disc(const std::filesystem::path& project){
    const auto* selected=_wgetenv(L"KX3_ISO");
    if(!selected || !*selected)return;
    const auto path=std::filesystem::absolute(selected).lexically_normal();
    if(path==last_disc(project))return;
    const auto bytes=utf8(path.native());
    try{
        replace_save_file_atomic(project/"local/pc-core/player/last-disc.txt",
            {reinterpret_cast<const std::uint8_t*>(bytes.data()),bytes.size()});
    }catch(const std::exception&){OutputDebugStringW(L"Could not store the selected disc location\n");}
}
int run(const std::filesystem::path& project,bool verify,StoryLanguage initial,bool menu_test,unsigned prefs_test,unsigned extra_test){
    struct BufferedPainting {
        BufferedPainting(){require(SUCCEEDED(BufferedPaintInit()),"Could not initialize buffered painting");}
        ~BufferedPainting(){BufferedPaintUnInit();}
    } buffered_painting;
    Player p(project,verify,initial,menu_test,prefs_test,extra_test);
    if(!verify)remember_disc(project); // Player has verified the ELF and mounted this edition's source files.
    WNDCLASSW cls{};cls.hInstance=GetModuleHandleW(nullptr);cls.lpfnWndProc=messages;
    cls.lpszClassName=L"KamaitachiNativePlayer1";cls.hCursor=LoadCursorW(nullptr,IDC_ARROW);
    require(RegisterClassW(&cls)!=0,"Could not register player window");
    RECT r{0,0,1120,700};AdjustWindowRect(&r,WS_OVERLAPPEDWINDOW,FALSE);
    auto wnd=CreateWindowExW(0,cls.lpszClassName,title,WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,
                             r.right-r.left,r.bottom-r.top,nullptr,nullptr,cls.hInstance,&p);
    require(wnd!=nullptr,"Could not open player window");
    p.refresh_caption();ShowWindow(wnd,verify?SW_SHOWNOACTIVATE:SW_SHOW);UpdateWindow(wnd);
    if(verify)PostMessageW(wnd,verify_msg,0,0);
    struct FrameDeadline{
        HANDLE handle=CreateWaitableTimerExW(nullptr,nullptr,CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                                             TIMER_MODIFY_STATE|SYNCHRONIZE);
        FrameDeadline(){
            if(!handle)handle=CreateWaitableTimerW(nullptr,FALSE,nullptr);
            require(handle!=nullptr,"Cannot create frame clock");
        }
        ~FrameDeadline(){CloseHandle(handle);}
    } deadline;
    MSG msg{};bool playing=false,done=false;
    while(!done){
        // Process queued input before advancing the original pad state.
        for(unsigned i=0;i<64 && PeekMessageW(&msg,nullptr,0,0,PM_REMOVE);++i){
            if(msg.message==WM_QUIT){done=true;break;}
            TranslateMessage(&msg);DispatchMessageW(&msg);
        }
        if(done)break;
        if(!p.running_clock()){
            if(playing)CancelWaitableTimer(deadline.handle);
            playing=false;
            require(MsgWaitForMultipleObjectsEx(0,nullptr,INFINITE,QS_ALLINPUT,MWMO_INPUTAVAILABLE)!=WAIT_FAILED,"Window wait failed");
            continue;
        }
        if(!playing){p.next=Clock::now()+cycle;playing=true;}
        if(Clock::now()>=p.next){p.timer();UpdateWindow(wnd);}
        LARGE_INTEGER due{};
        const auto ns=std::chrono::duration_cast<std::chrono::nanoseconds>(p.next-Clock::now()).count();
        due.QuadPart=-std::max<long long>(1,(ns+99)/100);
        require(SetWaitableTimer(deadline.handle,&due,0,nullptr,nullptr,FALSE)!=0,"Cannot arm frame clock");
        require(MsgWaitForMultipleObjectsEx(1,&deadline.handle,INFINITE,QS_ALLINPUT,MWMO_INPUTAVAILABLE)!=WAIT_FAILED,"Frame wait failed");
    }
    p.finish_timings();
    UnregisterClassW(cls.lpszClassName,cls.hInstance);
    return static_cast<int>(msg.wParam);
}
}
}

static bool select_startup_disc(const std::filesystem::path& root,std::filesystem::path iso,bool verify){
    if(iso.empty()){
        if(verify || std::filesystem::is_regular_file(kx3::platform::windows::game_disc_path(root)))return true;
        iso=kx3::platform::windows::last_disc(root);
        if(!iso.empty()){
            try{
                kx3::RetailDisc disc(iso,kx3::platform::windows::source_bytes_sha256);
                if(kx3::platform::windows::source_bytes_sha256(disc.read("SLPM_664.52",1290132))!=
                   "50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160")iso.clear();
            }catch(const std::exception&){iso.clear();}
        }
    }
    if(iso.empty()){
        wchar_t file[32768]{};
        OPENFILENAMEW picker{};
        picker.lStructSize=sizeof(picker);picker.lpstrFile=file;picker.nMaxFile=std::size(file);
        picker.lpstrTitle=L"选择原版游戏光盘 · Select the original game disc";
        picker.lpstrFilter=L"PlayStation 2 disc image (*.iso)\0*.iso\0";
        picker.lpstrInitialDir=root.c_str();
        picker.Flags=OFN_FILEMUSTEXIST|OFN_PATHMUSTEXIST|OFN_NOCHANGEDIR|OFN_EXPLORER;
        if(!GetOpenFileNameW(&picker)){
            const auto error=CommDlgExtendedError();
            if(error)throw std::runtime_error("Could not open disc picker: "+std::to_string(error));
            return false;
        }
        iso=file;
    }
    if(!std::filesystem::is_regular_file(iso))throw std::runtime_error("Selected game ISO was not found");
    if(_wputenv_s(L"KX3_ISO",std::filesystem::absolute(iso).c_str())!=0)
        throw std::runtime_error("Could not set the selected game disc for this session");
    return true;
}

int WINAPI wWinMain(HINSTANCE,HINSTANCE,LPWSTR,int){
    int argc=0;auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    std::filesystem::path root,iso;bool verify=false,english_first=false,menu_test=false;unsigned prefs_test=0,extra_test=0;
    for(int i=1;i<argc;++i){
        const std::wstring_view arg=argv[i];
        if(arg.starts_with(L"--verify")){LocalFree(argv);return 2;}
        else if(_wcsicmp(std::filesystem::path(argv[i]).extension().c_str(),L".iso")==0)iso=argv[i];
        else root=argv[i];
    }
    LocalFree(argv);
    if(root.empty()){
        wchar_t path[32768];const auto n=GetModuleFileNameW(nullptr,path,32768);
        if(!n || n>=32768)return 2;
        root=std::filesystem::path(path).parent_path().parent_path().parent_path().parent_path();
    }
    const auto com=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);int result=2;
    try{
        SetProcessDPIAware();
        result=select_startup_disc(root,iso,verify)?kx3::platform::windows::run(root,verify,english_first?kx3::platform::StoryLanguage::english:kx3::platform::StoryLanguage::chinese,menu_test,prefs_test,extra_test):0;
    }catch(const std::exception& e){
        if(verify)std::ofstream(root/"analysis/native-core/player-window.json")<<"{\"status\":\"failed\",\"error\":"<<std::quoted(e.what())<<"}";
        else MessageBoxA(nullptr,e.what(),"Kamaitachi native player",MB_ICONERROR|MB_OK);
    }
    if(SUCCEEDED(com))CoUninitialize();return result;
}
