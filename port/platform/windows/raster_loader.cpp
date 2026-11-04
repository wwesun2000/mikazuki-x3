#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincodec.h>
#include <bcrypt.h>

#include "raster_loader.hpp"
#include "../../core/retail_disc.hpp"
#include <cstdlib>
#include <memory>
#include <mutex>
#include <array>
#include <algorithm>
#include <limits>
#include <span>
#include <sstream>

namespace kx3::platform::windows {
namespace {
[[noreturn]] void fail(RasterFailure code, const std::string& message) {
    throw RasterLoadError(code, message);
}
void check(HRESULT result, const char* stage, RasterFailure failure = RasterFailure::codec) {
    if (FAILED(result)) {
        std::ostringstream message;
        message << stage << " failed (HRESULT 0x" << std::hex << static_cast<std::uint32_t>(result) << ')';
        fail(failure, message.str());
    }
}
struct File {
    HANDLE handle = INVALID_HANDLE_VALUE;
    ~File() { if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }
};
template<class T> struct ComPtr {
    T* value = nullptr;
    ~ComPtr() { if (value) value->Release(); }
    ComPtr() = default;
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;
    T* operator->() const noexcept { return value; }
    T** put() noexcept { return &value; }
};
struct Apartment {
    bool owned = false;
    Apartment() {
        const HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        // An existing STA is usable for this synchronous in-process WIC work;
        // a failed changed-mode call must not uninitialize the caller's COM.
        if (result == RPC_E_CHANGED_MODE) return;
        check(result, "CoInitializeEx", RasterFailure::system);
        owned = true; // Includes S_FALSE: each successful call is balanced.
    }
    ~Apartment() { if (owned) CoUninitialize(); }
};
struct Algorithm {
    BCRYPT_ALG_HANDLE value = nullptr;
    ~Algorithm() { if (value) BCryptCloseAlgorithmProvider(value, 0); }
};
struct Hash {
    BCRYPT_HASH_HANDLE value = nullptr;
    ~Hash() { if (value) BCryptDestroyHash(value); }
};
void check_nt(NTSTATUS status, const char* stage) {
    if (status < 0) fail(RasterFailure::system, std::string(stage) + " failed");
}
std::string sha256(std::span<const std::uint8_t> bytes) {
    Algorithm algorithm;
    check_nt(BCryptOpenAlgorithmProvider(&algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0), "BCryptOpenAlgorithmProvider");
    DWORD object_size = 0, received = 0;
    check_nt(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PUCHAR>(&object_size), sizeof(object_size), &received, 0), "BCryptGetProperty");
    if (received != sizeof(object_size) || object_size > 1024 * 1024)
        fail(RasterFailure::system, "Unexpected SHA256 provider object size");
    std::vector<std::uint8_t> object(object_size);
    Hash hash; // Destroy before the backing object and provider.
    check_nt(BCryptCreateHash(algorithm.value, &hash.value, object.data(), object_size, nullptr, 0, 0), "BCryptCreateHash");
    for (std::size_t cursor = 0; cursor < bytes.size();) {
        const auto count = static_cast<ULONG>(std::min<std::size_t>(bytes.size() - cursor, 1024 * 1024));
        check_nt(BCryptHashData(hash.value, const_cast<PUCHAR>(bytes.data() + cursor), count, 0), "BCryptHashData");
        cursor += count;
    }
    std::array<std::uint8_t, 32> digest{};
    check_nt(BCryptFinishHash(hash.value, digest.data(), static_cast<ULONG>(digest.size()), 0), "BCryptFinishHash");
    std::string result; result.reserve(64);
    constexpr char hex[] = "0123456789abcdef";
    for (auto byte : digest) { result.push_back(hex[byte >> 4]); result.push_back(hex[byte & 15]); }
    return result;
}
std::string normalize_hash(std::string value) {
    if (value.size() != 64) fail(RasterFailure::hash_mismatch, "Expected PNG SHA256 must have 64 hex characters");
    for (char& ch : value) {
        if (ch >= 'A' && ch <= 'F') ch = static_cast<char>(ch + ('a' - 'A'));
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')))
            fail(RasterFailure::hash_mismatch, "Expected PNG SHA256 is not hexadecimal");
    }
    return value;
}
std::uint32_t big32(const std::uint8_t* data) {
    return (std::uint32_t(data[0]) << 24) | (std::uint32_t(data[1]) << 16) |
           (std::uint32_t(data[2]) << 8) | data[3];
}
std::uint64_t checked_layout(std::uint32_t width, std::uint32_t height, const RasterDecodeLimits& limits) {
    if (!width || !height) fail(RasterFailure::dimensions, "PNG dimensions must be nonzero");
    // The fixed hard cap also bounds caller-provided limits and multiplication.
    if (width > limits.max_dimension || height > limits.max_dimension || width > 8192 || height > 8192)
        fail(RasterFailure::limit, "PNG dimension limit exceeded");
    const std::uint64_t bytes = std::uint64_t(width) * height * 4;
    if (bytes > limits.max_rgba_bytes || bytes > 128ull * 1024 * 1024 ||
        bytes > std::numeric_limits<UINT>::max() || bytes > std::numeric_limits<std::size_t>::max())
        fail(RasterFailure::limit, "Decoded RGBA byte limit exceeded");
    return bytes;
}
}

std::string source_bytes_sha256(std::span<const std::uint8_t> bytes) { return sha256(bytes); }
std::filesystem::path game_disc_path(const std::filesystem::path& root){
    const auto* source=_wgetenv(L"KX3_ISO");
    return std::filesystem::absolute(source && *source?std::filesystem::path(source):
        root/L"Kamaitachi no Yoru X3 - Mikazuki-jima Jiken no Shinsou (Japan).iso").lexically_normal();
}
namespace {
std::mutex disc_lock;
// Callers hold disc_lock while using the returned image.
RetailDisc& mounted_game_disc(const std::filesystem::path& root){
    const auto iso=game_disc_path(root);
    static std::unique_ptr<RetailDisc> disc;
    static std::filesystem::path mounted;
    if(!disc || mounted!=iso){
        auto candidate=std::make_unique<RetailDisc>(iso,source_bytes_sha256);
        mounted=iso;disc=std::move(candidate);
    }
    return *disc;
}
}
std::uint64_t disc_resource_size(const std::filesystem::path& root,std::string_view member) {
    std::lock_guard guard(disc_lock);
    return mounted_game_disc(root).member_size(member);
}
std::vector<std::uint8_t> read_disc_resource(const std::filesystem::path& root,std::string_view member,
                                             const std::string& expected_sha,std::uint64_t expected_size) {
    std::vector<std::uint8_t> bytes;
    {
        std::lock_guard guard(disc_lock);
        bytes=mounted_game_disc(root).read(member,expected_size);
    }
    if(source_bytes_sha256(bytes)!=expected_sha)throw std::runtime_error("ISO resource hash mismatch: "+std::string(member));
    return bytes;
}
std::vector<std::uint8_t> read_verified_source(const std::filesystem::path& path,const std::string& expected_sha,std::uint64_t expected_size) {
    if(!expected_size || expected_size>64ull*1024*1024) fail(RasterFailure::limit,"Original asset size limit exceeded");
    const auto hash=normalize_hash(expected_sha);
    File file;
    file.handle=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file.handle==INVALID_HANDLE_VALUE) fail(RasterFailure::io,"Cannot open original encoded asset");
    LARGE_INTEGER size{};
    if(!GetFileSizeEx(file.handle,&size) || size.QuadPart!=static_cast<LONGLONG>(expected_size))
        fail(RasterFailure::io,"Original encoded asset size mismatch");
    std::vector<std::uint8_t> data(static_cast<std::size_t>(expected_size));
    DWORD read=0;
    if(!ReadFile(file.handle,data.data(),DWORD(data.size()),&read,nullptr) || read!=data.size())
        fail(RasterFailure::io,"Incomplete original asset read");
    if(sha256(data)!=hash) fail(RasterFailure::hash_mismatch,"Original encoded asset SHA256 mismatch");
    return data;
}

void verify_encoded_source(const std::filesystem::path& path,const std::string& expected_sha,std::uint64_t expected_size) {
    (void)read_verified_source(path,expected_sha,expected_size);
}

RasterLoadResult load_png_rgba(const std::filesystem::path& path, const PngExpectation& expected,
                              const RasterDecodeLimits& limits) {
    const auto expected_hash = normalize_hash(expected.sha256);
    const auto rgba_bytes = checked_layout(expected.width, expected.height, limits);
    File file;
    file.handle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file.handle == INVALID_HANDLE_VALUE) fail(RasterFailure::io, "Cannot open PNG input");
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file.handle, &length) || length.QuadPart <= 0)
        fail(RasterFailure::io, "Cannot determine nonempty PNG size");
    const auto encoded_size = static_cast<std::uint64_t>(length.QuadPart);
    if (encoded_size > limits.max_encoded_bytes || encoded_size > 64ull * 1024 * 1024)
        fail(RasterFailure::limit, "Encoded PNG byte limit exceeded");
    // This buffer outlives all WIC stream/decoder objects and is hashed once.
    std::vector<std::uint8_t> encoded(static_cast<std::size_t>(encoded_size));
    std::size_t cursor = 0;
    while (cursor < encoded.size()) {
        DWORD read = 0;
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(encoded.size() - cursor, 1024 * 1024));
        if (!ReadFile(file.handle, encoded.data() + cursor, requested, &read, nullptr) || read == 0)
            fail(RasterFailure::io, "Incomplete PNG read");
        cursor += read;
    }
    const auto png_hash = sha256(encoded);
    if (png_hash != expected_hash) fail(RasterFailure::hash_mismatch, "PNG SHA256 mismatch");
    constexpr std::array<std::uint8_t, 8> signature{137,80,78,71,13,10,26,10};
    if (encoded.size() < 33 || !std::equal(signature.begin(), signature.end(), encoded.begin()) ||
        big32(encoded.data() + 8) != 13 || !std::equal(encoded.begin() + 12, encoded.begin() + 16, "IHDR"))
        fail(RasterFailure::invalid_png, "Missing PNG signature or canonical IHDR");
    const auto header_width = big32(encoded.data() + 16), header_height = big32(encoded.data() + 20);
    checked_layout(header_width, header_height, limits);
    if (header_width != expected.width || header_height != expected.height)
        fail(RasterFailure::dimensions, "PNG dimensions differ from expected asset");

    Apartment apartment; // COM interfaces below release before this scope ends.
    ComPtr<IWICImagingFactory> factory;
    check(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER,
                           IID_IWICImagingFactory, reinterpret_cast<void**>(factory.put())), "Create WIC factory");
    ComPtr<IWICStream> stream;
    check(factory->CreateStream(stream.put()), "Create WIC stream");
    check(stream->InitializeFromMemory(encoded.data(), static_cast<DWORD>(encoded.size())), "Initialize WIC stream");
    ComPtr<IWICBitmapDecoder> decoder;
    check(factory->CreateDecoderFromStream(stream.value, nullptr, WICDecodeMetadataCacheOnLoad, decoder.put()), "Decode PNG");
    GUID container{};
    check(decoder->GetContainerFormat(&container), "Read container format");
    if (!IsEqualGUID(container, GUID_ContainerFormatPng)) fail(RasterFailure::invalid_png, "WIC input is not PNG");
    UINT count = 0;
    check(decoder->GetFrameCount(&count), "Read frame count");
    if (count != 1) fail(RasterFailure::invalid_png, "Expected exactly one raster frame");
    ComPtr<IWICBitmapFrameDecode> decoded;
    check(decoder->GetFrame(0, decoded.put()), "Read PNG frame");
    UINT width = 0, height = 0;
    check(decoded->GetSize(&width, &height), "Read decoded dimensions");
    if (width != expected.width || height != expected.height) fail(RasterFailure::dimensions, "WIC dimensions mismatch");
    ComPtr<IWICFormatConverter> converter;
    check(factory->CreateFormatConverter(converter.put()), "Create RGBA converter");
    check(converter->Initialize(decoded.value, GUID_WICPixelFormat32bppRGBA,
        WICBitmapDitherTypeNone, nullptr, 0.0, WICBitmapPaletteTypeCustom), "Convert to straight RGBA8");
    auto frame = std::make_shared<RasterFrame>();
    frame->width = width; frame->height = height; frame->rgba.resize(static_cast<std::size_t>(rgba_bytes));
    check(converter->CopyPixels(nullptr, width * 4, static_cast<UINT>(rgba_bytes), frame->rgba.data()), "Copy RGBA pixels");
    RasterLoadResult result;
    result.png_sha256 = png_hash; result.rgba_sha256 = sha256(frame->rgba);
    result.encoded_bytes = encoded_size; result.frame = std::move(frame);
    return result;
}
}
