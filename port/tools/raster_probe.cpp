#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include "../platform/windows/raster_loader.hpp"
#include <iostream>
#include <limits>

using namespace kx3::platform::windows;
namespace {
void require(bool condition, const char* message) { if (!condition) throw std::runtime_error(message); }
std::string ascii(const wchar_t* value) {
    std::string result;
    while (*value) { if (*value > 127) throw std::runtime_error("Hash must be ASCII hex"); result.push_back(static_cast<char>(*value++)); }
    return result;
}
std::uint32_t dimension(const wchar_t* value) {
    std::wstring text(value); std::size_t consumed = 0;
    const auto parsed = std::stoull(text, &consumed);
    if (consumed != text.size() || parsed > std::numeric_limits<std::uint32_t>::max()) throw std::runtime_error("Invalid dimension");
    return static_cast<std::uint32_t>(parsed);
}
template<class F> void rejects(F action, RasterFailure expected) {
    try { action(); } catch (const RasterLoadError& error) { require(error.code() == expected, "Wrong rejection reason"); return; }
    throw std::runtime_error("Invalid load unexpectedly succeeded");
}
struct ComBalance { ~ComBalance() { CoUninitialize(); } };
}
int wmain(int argc, wchar_t** argv) {
    try {
        if (argc != 5) throw std::runtime_error("Usage: raster_probe PNG expectedSHA width height");
        const std::filesystem::path path(argv[1]);
        const PngExpectation expected{ascii(argv[2]), dimension(argv[3]), dimension(argv[4])};
        const auto raster = load_png_rgba(path, expected);
        require(raster.frame && raster.frame->rgba.size() == std::uint64_t(expected.width) * expected.height * 4, "Invalid returned raster");
        auto wrong_hash = expected; wrong_hash.sha256[0] = wrong_hash.sha256[0] == '0' ? '1' : '0';
        rejects([&] { (void)load_png_rgba(path, wrong_hash); }, RasterFailure::hash_mismatch);
        auto wrong_dimensions = expected; ++wrong_dimensions.width;
        rejects([&] { (void)load_png_rgba(path, wrong_dimensions); }, RasterFailure::dimensions);
        RasterDecodeLimits low_limit; low_limit.max_rgba_bytes = raster.frame->rgba.size() - 1;
        rejects([&] { (void)load_png_rgba(path, expected, low_limit); }, RasterFailure::limit);
        // A successful fresh STA init proves our previous MTA call was balanced.
        const auto sta = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        require(sta == S_OK, "Loader leaked its COM apartment initialization");
        {
            ComBalance balance;
            const auto second = load_png_rgba(path, expected);
            require(second.rgba_sha256 == raster.rgba_sha256, "Existing STA changed decode result");
            const auto mode_check = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            if (SUCCEEDED(mode_check)) CoUninitialize();
            require(mode_check == RPC_E_CHANGED_MODE, "Loader uninitialized caller COM apartment");
        }
        std::uint64_t opaque = 0, nonblack = 0;
        for (std::size_t i = 0; i < raster.frame->rgba.size(); i += 4) {
            opaque += raster.frame->rgba[i + 3] == 255;
            nonblack += raster.frame->rgba[i] != 0 || raster.frame->rgba[i + 1] != 0 || raster.frame->rgba[i + 2] != 0;
        }
        std::cout << "{\"status\":\"passed\",\"decoder\":\"Windows WIC RGBA8 straight alpha\",\"width\":" << raster.frame->width
                  << ",\"height\":" << raster.frame->height << ",\"encoded_bytes\":" << raster.encoded_bytes
                  << ",\"rgba_bytes\":" << raster.frame->rgba.size() << ",\"png_sha256\":\"" << raster.png_sha256
                  << "\",\"rgba_sha256\":\"" << raster.rgba_sha256 << "\",\"opaque_pixels\":" << opaque
                  << ",\"nonblack_pixels\":" << nonblack
                  << ",\"wrong_hash_rejected\":true,\"wrong_dimensions_rejected\":true,\"rgba_limit_rejected\":true,\"com_lifecycle_passed\":true}\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "raster_probe: " << error.what() << '\n'; return 1; }
}
