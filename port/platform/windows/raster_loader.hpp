#pragma once

#include "../raster_frame.hpp"
#include <filesystem>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>

namespace kx3::platform::windows {
struct PngExpectation {
    std::string sha256; // Exactly 64 hexadecimal characters, checked before WIC.
    std::uint32_t width = 0;
    std::uint32_t height = 0;
};
struct RasterDecodeLimits {
    std::uint32_t max_dimension = 8192;
    std::uint64_t max_encoded_bytes = 64ull * 1024 * 1024;
    std::uint64_t max_rgba_bytes = 128ull * 1024 * 1024;
};
enum class RasterFailure { io, hash_mismatch, invalid_png, dimensions, limit, codec, system };
class RasterLoadError final : public std::runtime_error {
public:
    RasterLoadError(RasterFailure code, const std::string& message)
        : std::runtime_error(message), code_(code) {}
    RasterFailure code() const noexcept { return code_; }
private:
    RasterFailure code_;
};
struct RasterLoadResult {
    std::shared_ptr<const RasterFrame> frame;
    std::string png_sha256;
    std::string rgba_sha256;
    std::uint64_t encoded_bytes = 0;
};

// Synchronous, independent of prepared/current media state. Throws without
// publishing a partial frame. Reads, hashes and decodes the same owned bytes.
RasterLoadResult load_png_rgba(const std::filesystem::path& path,
                              const PngExpectation& expected,
                              const RasterDecodeLimits& limits = {});
// Verify the original encoded asset associated with a certified derivative.
void verify_encoded_source(const std::filesystem::path&,const std::string& sha256,
                           std::uint64_t expected_size);
std::string source_bytes_sha256(std::span<const std::uint8_t> bytes);
std::filesystem::path game_disc_path(const std::filesystem::path& root);
std::uint64_t disc_resource_size(const std::filesystem::path& root,std::string_view member);
std::vector<std::uint8_t> read_disc_resource(const std::filesystem::path& root,std::string_view member,
                                             const std::string& sha256,std::uint64_t expected_size);
std::vector<std::uint8_t> read_verified_source(const std::filesystem::path&,const std::string& sha256,
                                              std::uint64_t expected_size);
}
