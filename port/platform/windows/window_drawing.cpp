#include "window_drawing.hpp"
#include <wincodec.h>
#include <cstdint>
#include <vector>
#include <stdexcept>
#include <fstream>
#include <iterator>
#include <algorithm>

namespace kx3::platform::windows {
HFONT create_ui_font(int height,int weight,const wchar_t* face){
    return CreateFontW(-height,0,0,0,weight,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,face);
}
void draw_ui_text(HDC dc,RECT rect,const wchar_t* text,HFONT font,COLORREF color,UINT format){
    auto old=SelectObject(dc,font);
    SetBkMode(dc,TRANSPARENT);
    SetTextColor(dc,color);
    DrawTextW(dc,text,-1,&rect,format|DT_NOPREFIX);
    SelectObject(dc,old);
}
static void require(bool ok,const char* message){ if(!ok)throw std::runtime_error(message); }
template<class T>struct Com {T* p=nullptr;~Com(){if(p)p->Release();}};
void ok(HRESULT result){if(FAILED(result))throw std::runtime_error("Could not write window capture");}
std::filesystem::path capture_window_client(HWND window,std::filesystem::path path,bool keep_history){
    const auto previous_path=path;
    GUID id{};ok(CoCreateGuid(&id));wchar_t unique[40]{};
    require(StringFromGUID2(id,unique,std::size(unique))!=0,"Cannot allocate screenshot name");
    struct Pending {std::filesystem::path file;~Pending(){DeleteFileW(file.c_str());}};
    const Pending temp{path.parent_path()/(std::wstring(L".capture-")+unique+L".tmp")};
    RECT r{};GetClientRect(window,&r);const int w=r.right,h=r.bottom;
    require(w>0 && h>0,"Cannot capture an empty client area");
    std::vector<BYTE> bgra(std::size_t(w)*h*4);
    HDC dc=CreateCompatibleDC(nullptr);require(dc!=nullptr,"Capture DC unavailable");
    BITMAPINFO info{};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=w;info.bmiHeader.biHeight=-h;
    info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;void* bits=nullptr;
    const auto bitmap=CreateDIBSection(dc,&info,DIB_RGB_COLORS,&bits,nullptr,0);
    if(!bitmap || !bits){if(bitmap)DeleteObject(bitmap);DeleteDC(dc);throw std::runtime_error("Capture buffer unavailable");}
    const auto previous=SelectObject(dc,bitmap);
    SendMessageW(window,WM_PRINTCLIENT,WPARAM(dc),PRF_CLIENT);GdiFlush();
    std::copy_n(static_cast<BYTE*>(bits),bgra.size(),bgra.begin());
    SelectObject(dc,previous);DeleteObject(bitmap);DeleteDC(dc);
    for(std::size_t i=3;i<bgra.size();i+=4)bgra[i]=255;
    std::filesystem::create_directories(path.parent_path());
    {
    Com<IWICImagingFactory> factory;ok(CoCreateInstance(CLSID_WICImagingFactory,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&factory.p)));
    Com<IWICStream> stream;ok(factory.p->CreateStream(&stream.p));ok(stream.p->InitializeFromFilename(temp.file.c_str(),GENERIC_WRITE));
    Com<IWICBitmapEncoder> enc;ok(factory.p->CreateEncoder(GUID_ContainerFormatPng,nullptr,&enc.p));ok(enc.p->Initialize(stream.p,WICBitmapEncoderNoCache));
    Com<IWICBitmapFrameEncode> frame;Com<IPropertyBag2> properties;ok(enc.p->CreateNewFrame(&frame.p,&properties.p));
    ok(frame.p->Initialize(properties.p));ok(frame.p->SetSize(w,h));WICPixelFormatGUID pixel=GUID_WICPixelFormat32bppBGRA;
    ok(frame.p->SetPixelFormat(&pixel));require(IsEqualGUID(pixel,GUID_WICPixelFormat32bppBGRA),"Capture pixel format changed");
    ok(frame.p->WritePixels(h,w*4,UINT(bgra.size()),bgra.data()));ok(frame.p->Commit());ok(enc.p->Commit());
    }
    // A verification rerun can paint the same exact PNG. Keep its original
    // registered filename and avoid retaining a duplicate capture on disk.
    if(!keep_history){
        require(MoveFileExW(temp.file.c_str(),previous_path.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=0,"Could not refresh the QA screenshot");
        return previous_path;
    }
    const auto encoded_size=std::filesystem::file_size(temp.file);
    auto identical=[&](const std::filesystem::path& candidate){
        if(std::filesystem::file_size(candidate)!=encoded_size)return false;
        std::ifstream a(temp.file,std::ios::binary),b(candidate,std::ios::binary);
        using Bytes=std::istreambuf_iterator<char>;
        return a && b && std::equal(Bytes(a),Bytes(),Bytes(b),Bytes()) && !a.bad() && !b.bad();
    };
    auto publish=[&](const std::filesystem::path& candidate){
        if(MoveFileExW(temp.file.c_str(),candidate.c_str(),MOVEFILE_WRITE_THROUGH))return true;
        const auto error=GetLastError();
        require(error==ERROR_ALREADY_EXISTS || error==ERROR_FILE_EXISTS,"Could not publish screenshot");
        return identical(candidate);
    };
    if(publish(path))return path;
    // Earlier captures used GUID suffixes. Only match this exact display
    // configuration: a "-scan" screenshot may have identical black pixels.
    const auto legacy_prefix=path.stem().wstring()+L"-{";
    for(const auto& entry:std::filesystem::directory_iterator(path.parent_path())){
        const auto& candidate=entry.path();
        const auto stem=candidate.stem().wstring();
        if(entry.is_regular_file() && candidate.extension()==path.extension() &&
           stem.size()==legacy_prefix.size()+37 && stem.starts_with(legacy_prefix) &&
           stem.ends_with(L"}") && identical(candidate))return candidate;
    }
    for(std::uint64_t n=2;;++n){
        const auto variant=path.parent_path()/(path.stem().wstring()+L"-v"+std::to_wstring(n)+L".png");
        if(publish(variant))return variant;
    }
}

}
