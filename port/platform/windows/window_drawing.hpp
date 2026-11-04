#pragma once
#define NOMINMAX
#include <windows.h>
#include <filesystem>

namespace kx3::platform::windows {
HFONT create_ui_font(int pixel_height, int weight, const wchar_t* face=L"Microsoft YaHei UI");
void draw_ui_text(HDC dc, RECT rect, const wchar_t* text, HFONT font, COLORREF color, UINT format);
std::filesystem::path capture_window_client(HWND window, std::filesystem::path path,bool keep_history=true);
}
