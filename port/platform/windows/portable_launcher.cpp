// Native GUI entry for the portable distribution; no command shell is used.
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <string>

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR arguments, int) {
    wchar_t path[32768];
    const DWORD length = GetModuleFileNameW(nullptr, path, 32768);
    if (!length || length >= 32768) return 2;
    std::wstring root(path, length);
    root.resize(root.find_last_of(L"\\/"));
    const auto player = root + L"\\local\\pc-core\\player\\KamaitachiX3.exe";
    std::wstring command = L"\"" + player + L"\" \"" + root + L"\"";
    if (arguments && *arguments) command += L" " + std::wstring(arguments);
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(player.c_str(), command.data(), nullptr, nullptr, FALSE,
                        0, nullptr, root.c_str(), &startup, &process)) {
        MessageBoxW(nullptr,
            L"Unable to start the player. Extract the complete ZIP and keep its subfolders.\n"
            L"\x65e0\x6cd5\x542f\x52a8\x64ad\x653e\x5668\x3002\x8bf7\x5b8c\x6574\x89e3\x538b ZIP\x5e76\x4fdd\x7559\x5b50\x76ee\x5f55\x3002",
            L"Mikazuki X3", MB_OK | MB_ICONERROR);
        return 2;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 0;
}
