#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace kx3 {
class GuestMemory;

// The exact original 137578/137598 -> 1375D8 argument boundary. A descriptor is
// a guest pointer returned by source registry101B58, never an inferred filename.
struct MediaRequest {
    std::uint32_t caller_entry;
    std::uint32_t descriptor;
    std::uint32_t token_address;
    std::vector<std::uint8_t> token_bytes;
    std::uint64_t auxiliary;
    std::uint64_t active;
    std::uint64_t kind;
};

class MissingMediaBackend : public std::runtime_error {
public:
    MediaRequest request;
    explicit MissingMediaBackend(MediaRequest value);
};

class MediaCommandBackend {
public:
    virtual ~MediaCommandBackend() = default;
    // Called only after original1373B8 permits the active branch. Must implement
    // its whole remaining effect sequence (1376A4 onward), including filename
    // storage, 1384B0 resource preparation, audio preservation/cleanup and final
    // 1378B0 preparation. A log-only backend must throw, not return success.
    // Supply the original low64 v0 at return. A modern adapter needs an explicit
    // contract for guest state and its own checkpoint/rollback; no default exists.
    virtual std::uint64_t execute_active(GuestMemory&, const MediaRequest&) = 0;
    virtual std::vector<std::uint8_t> read_panel_member(const std::string&) const {
        throw std::runtime_error("Missing ISO panel file service at 1453A8");
    }
    // Standalone 137D78 loader task. Script polling and game ticks have distinct
    // lifetimes. Call with the same transactional asset owner as the game.
    virtual void step_deferred(GuestMemory&) { throw std::runtime_error("Unported source loader worker 0x00137d78"); }
    virtual void finish_deferred(GuestMemory&) { throw std::runtime_error("Unported source scene completion 0x00135660"); }
    virtual void adopt_completed_scene(const GuestMemory&) { throw std::runtime_error("Unbound scene completion at 0x001356f4"); }
    virtual void consume_image_start(GuestMemory&) { throw std::runtime_error("Unported source decoder task 0x0013f208"); }
    virtual void begin_frame() { throw std::logic_error("Media backend does not support atomic manager frames"); }
    virtual void end_frame(bool) noexcept {}
};

void tick_deferred_scene(GuestMemory&, MediaCommandBackend&);

[[nodiscard]] bool has_media_command(std::uint32_t entry) noexcept;
[[nodiscard]] std::uint64_t invoke_media_command(
    GuestMemory&, std::uint32_t entry, std::uint32_t self,
    std::uint64_t a1 = 0, std::uint64_t a2 = 0, std::uint64_t a3 = 0,
    std::uint32_t gp = 0, MediaCommandBackend* backend = nullptr);
}
