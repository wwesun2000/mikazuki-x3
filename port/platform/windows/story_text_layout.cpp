#include "story_text_layout.hpp"
#include <algorithm>
#include <stdexcept>

namespace kx3::platform::windows {
namespace {
struct ColorRun {size_t start;COLORREF color;};
struct Row { RECT rect;std::wstring text;unsigned opacity;int option;int x,y;bool name;std::vector<ColorRun> colors; };
constexpr UINT flags=DT_LEFT|DT_TOP|DT_WORDBREAK|DT_NOPREFIX;
std::wstring utf16(std::string_view value,bool name){
    const UINT cp=name?932:CP_UTF8;
    const int n=MultiByteToWideChar(cp,MB_ERR_INVALID_CHARS,value.data(),int(value.size()),nullptr,0);
    if(n<=0)throw std::runtime_error("Invalid player name or translated text");
    std::wstring result(n,L' ');
    MultiByteToWideChar(cp,MB_ERR_INVALID_CHARS,value.data(),int(value.size()),result.data(),n);
    return result;
}
// Use the same measured line for every ink run. A differently colored player
// name can occur between two clauses, including in the middle of a wrapped line.
int colored_text(HDC dc,RECT area,const Row& row,bool paint,int thickness){
    TEXTMETRICW tm{};GetTextMetricsW(dc,&tm);
    const int width=std::max(1L,area.right-area.left);int y=area.top;
    std::vector<WORD> glyphs(row.text.size());
    const auto mapped=GetGlyphIndicesW(dc,row.text.data(),int(row.text.size()),glyphs.data(),GGI_MARK_NONEXISTING_GLYPHS);
    const bool fallback=mapped==GDI_ERROR || std::ranges::find(glyphs,WORD(0xffff))!=glyphs.end();
    constexpr UINT single=DT_LEFT|DT_TOP|DT_SINGLELINE|DT_NOPREFIX|DT_NOCLIP;
    const auto measure=[&](const wchar_t* text,int count){
        RECT r{};
        if(count)DrawTextW(dc,text,count,&r,single|DT_CALCRECT);
        return SIZE{r.right-r.left,r.bottom-r.top};
    };
    std::vector<int> advance(row.text.size());std::size_t run=0;
    for(std::size_t at=0;at<row.text.size();){
        const wchar_t* text=row.text.data()+at;const int remain=int(row.text.size()-at);
        int fitted=0;SIZE extent{};
        GetTextExtentExPointW(dc,text,remain,width,&fitted,advance.data(),&extent);
        if(fallback){
            // TextOutW and its extents can use the missing-glyph box where
            // DrawTextW substitutes a linked font. Measure and paint with the
            // same fallback path, including the offset of every color run.
            std::vector<int> ends{0};
            for(int i=0;i<remain;){
                if(text[i]>=0xd800 && text[i]<=0xdbff && i+1<remain && text[i+1]>=0xdc00 && text[i+1]<=0xdfff)i+=2;
                else ++i;
                ends.push_back(i);
            }
            std::size_t lo=0,hi=ends.size()-1;
            while(lo<hi){
                const auto mid=lo+(hi-lo+1)/2;
                if(measure(text,ends[mid]).cx<=width)lo=mid;else hi=mid-1;
            }
            fitted=ends[lo?lo:1]; // Even a very narrow line keeps a full code point.
        }
        int count=std::max(1,fitted);
        if(count<remain){
            // Keep whole Latin words where possible. CJK breaks between characters.
            const auto word=[](wchar_t c){return (c>=L'a' && c<=L'z') || (c>=L'A' && c<=L'Z') || (c>=L'0' && c<=L'9') || c==0x2019 || c==0x27;};
            if(word(text[count-1]) && word(text[count])){
                int start=count;while(start && word(text[start-1]))--start;
                if(start)count=start;
            }
            if(count>1 && text[count-1]>=0xd800 && text[count-1]<=0xdbff)--count;
        }
        const int line_height=fallback?std::max(tm.tmHeight,measure(text,count).cy):tm.tmHeight;
        if(paint){
            for(int pos=0;pos<count;){
                while(run+1<row.colors.size() && row.colors[run+1].start<=at+pos)++run;
                const int end=run+1<row.colors.size()?std::min<std::size_t>(count,row.colors[run+1].start-at):count;
                const int x=area.left+(pos?(fallback?measure(text,pos).cx:advance[pos-1]):0);
                const auto draw=[&](int dx,int dy){
                    if(fallback){
                        RECT r{x+dx,y+dy,area.right+dx,y+dy+line_height};
                        DrawTextW(dc,text+pos,end-pos,&r,single);
                    }else TextOutW(dc,x+dx,y+dy,text+pos,end-pos);
                };
                SetTextColor(dc,RGB(10,13,17));
                for(int dx:{-thickness,0,thickness})for(int dy:{-thickness,0,thickness})if(dx||dy)
                    draw(dx,dy);
                SetTextColor(dc,row.colors[run].color);draw(0,0);pos=end;
            }
        }
        at+=count;y+=line_height;
    }
    return y;
}
void ink(HDC dc,RECT area,const Row& row,HFONT font,int thickness){
    if(row.colors.size()>1){
        const auto old=SelectObject(dc,font);const auto mode=SetBkMode(dc,TRANSPARENT);
        colored_text(dc,area,row,true,thickness);SetBkMode(dc,mode);SelectObject(dc,old);return;
    }
    for(int x:{-thickness,0,thickness})for(int y:{-thickness,0,thickness})if(x||y){
        RECT edge=area;OffsetRect(&edge,x,y);draw_ui_text(dc,edge,row.text.c_str(),font,RGB(10,13,17),flags);
    }
    draw_ui_text(dc,area,row.text.c_str(),font,row.colors.front().color,flags);
}
void paint(HDC dc,const Row& row,HFONT font,int thickness){
    if(row.opacity==255){ink(dc,row.rect,row,font,thickness);return;}
    const int width=row.rect.right-row.rect.left+2*thickness,height=row.rect.bottom-row.rect.top+2*thickness;
    if(width<=0 || height<=0)return;
    HDC off=CreateCompatibleDC(dc);if(!off)return;
    HBITMAP image=CreateCompatibleBitmap(dc,width,height);if(!image){DeleteDC(off);return;}
    auto old=SelectObject(off,image);
    const int x=row.rect.left-thickness,y=row.rect.top-thickness;
    BitBlt(off,0,0,width,height,dc,x,y,SRCCOPY);
    ink(off,{thickness,thickness,width-thickness,height-thickness},row,font,thickness);
    AlphaBlend(dc,x,y,width,height,off,0,0,width,height,{AC_SRC_OVER,0,BYTE(row.opacity),0});
    SelectObject(off,old);DeleteObject(image);DeleteDC(off);
}
}
unsigned draw_story_translation(HDC dc,RECT stage,std::span<const LocalizedLine> input,
                                std::vector<TranslatedOptionHit>& options){
    options.clear();
    if(input.empty())return 0;
    const LONG w=stage.right-stage.left,h=stage.bottom-stage.top;
    const int margin=std::max(4L,w/40);
    std::vector<Row> rows;
    rows.reserve(input.size());
    for(const auto& item:input){
        auto text=utf16(item.text,item.player_name_cp932);
        const auto color=RGB(item.rgb>>16,(item.rgb>>8)&255,item.rgb&255);
        // 10D4C8 inserts the player's name inline between two original text
        // fragments. Lay out the surrounding translated fragments as one row.
        const bool same_option=!rows.empty() && item.option>=0 && rows.back().option==item.option &&
                               rows.back().opacity==item.opacity;
        const bool inline_name=!rows.empty() && rows.back().y==item.y && rows.back().option==item.option &&
                               (rows.back().name || item.player_name_cp932);
        if(same_option || inline_name){
            auto& row=rows.back();
            // The original splits long choices at Japanese glyph coordinates.
            // Keep their source index but wrap the visible translation as one option.
            const auto latin=[](wchar_t c){return (c>=L'a'&&c<=L'z')||(c>=L'A'&&c<=L'Z')||(c>=L'0'&&c<=L'9');};
            // A source-bound unfinished prefix can end in a Latin word just
            // before the live name ("But I" + "Mari"). Keep the words separate;
            // apostrophes, explicit spaces and CJK adjacency retain their bytes.
            if(!row.text.empty() && !text.empty() &&
               latin(row.text.back()) && latin(text.front()))row.text+=L' ';
            if(row.colors.back().color!=color)row.colors.push_back({row.text.size(),color});
            row.text+=text;row.opacity=std::max(row.opacity,item.opacity);row.name=item.player_name_cp932;continue;
        }
        rows.push_back({{},std::move(text),item.opacity,item.option,item.x,item.y,item.player_name_cp932,{{0,color}}});
    }
    int size=std::clamp(int(h)*std::max(input.front().height,16)*2/(448*3),8,70);
    HFONT font=nullptr;
    for(;;--size){
        font=create_ui_font(size,FW_NORMAL);
        if(!font)throw std::runtime_error("System story font unavailable");
        const auto old=SelectObject(dc,font);
        LONG end=stage.top;
        for(std::size_t i=0;i<rows.size();++i){
            auto& row=rows[i];
            LONG left=stage.left+std::clamp(MulDiv(row.x,w,640),margin,int(w/2));
            LONG top=std::max(end,stage.top+MulDiv(row.y,h,448));
            RECT area{left,top,stage.right-margin,top};
            if(row.colors.size()>1)area.bottom=colored_text(dc,area,row,false,0);
            else DrawTextW(dc,row.text.c_str(),-1,&area,flags|DT_CALCRECT);
            row.rect={left,top,stage.right-margin,area.bottom};
            end=area.bottom+std::max(1,size/8);
        }
        SelectObject(dc,old);
        if(end<=stage.bottom-margin || size<=8)break;
        DeleteObject(font);
    }
    const int saved=SaveDC(dc);
    IntersectClipRect(dc,stage.left,stage.top,stage.right,stage.bottom);
    unsigned drawn=0;
    for(const auto& row:rows)if(row.opacity){
        paint(dc,row,font,std::max(1,size/22));++drawn;
        if(row.option>=0)options.push_back({row.rect,unsigned(row.option)});
    }
    RestoreDC(dc,saved);DeleteObject(font);
    return drawn;
}
RasterFrame raster_story_translation(HDC dc,std::span<const LocalizedLine> lines,
                                     std::vector<TranslatedOptionHit>& options){
    HDC off=CreateCompatibleDC(dc);
    if(!off)throw std::runtime_error("Text-effect DC unavailable");
    BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth=640;info.bmiHeader.biHeight=-448;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;
    void* bits=nullptr;const auto bitmap=CreateDIBSection(off,&info,DIB_RGB_COLORS,&bits,nullptr,0);
    if(!bitmap || !bits){if(bitmap)DeleteObject(bitmap);DeleteDC(off);throw std::runtime_error("Text-effect surface unavailable");}
    const auto old=SelectObject(off,bitmap);
    struct Release {HDC dc;HBITMAP bitmap;HGDIOBJ old;~Release(){SelectObject(dc,old);DeleteObject(bitmap);DeleteDC(dc);}} release{off,bitmap,old};
    std::fill_n(static_cast<std::uint32_t*>(bits),640*448,0u);
    draw_story_translation(off,{0,0,640,448},lines,options);GdiFlush();
    RasterFrame result{640,448,std::vector<std::uint8_t>(640*448*4)};
    const auto* pixels=static_cast<const std::uint8_t*>(bits);
    // The replacement font is rasterized against black. Preserve its measured
    // colored coverage; the core supplies every original blur offset and alpha.
    for(std::size_t i=0;i<result.rgba.size();i+=4){
        const unsigned coverage=std::max({pixels[i],pixels[i+1],pixels[i+2]});
        result.rgba[i+3]=coverage;
        if(coverage)for(unsigned c=0;c<3;++c)result.rgba[i+c]=std::uint8_t(unsigned(pixels[i+2-c])*255/coverage);
    }
    return result;
}

}
