#pragma once
#include <cstdint>
#include <span>

namespace kx3 {
class GuestMemory;
struct ExecutionServices;

struct TextGlyphRequest {
    std::uint32_t source_entry;
    std::uint32_t manager;
    std::uint32_t font;
    std::uint32_t source_address;
    std::uint16_t source_unit;
    std::uint16_t display_unit;
    bool ruby;
    std::uint32_t insertion_site=0; // Original script opcode which invoked a live-name block.
};

struct TextGlyphEvent {
    TextGlyphRequest source;
    std::uint32_t node_address; // Zero for source space advances.
    std::uint32_t metric_record;
    std::uint32_t atlas_address;
    std::int32_t x, y;
    std::uint32_t width, height;
    // -1 uses the channel atlas, 4 is original EFFECT/love.ctf.
    std::int32_t resource_atlas = -1;
};

class TextPresentationBackend {
public:
    virtual ~TextPresentationBackend() = default;
    // Native nodes/atlas are already updated. Copy events into the caller's
    // pending transaction, then publish only after its outer commit.
    virtual void stage_glyph_events(std::span<const TextGlyphEvent>) = 0;
    // 1114F8 clears both source node pools. Stage this alongside glyph events
    // so a host can discard the previous visible page only after commit.
    virtual void stage_page_clear() {}
};

[[nodiscard]] bool has_text_driver(std::uint32_t entry) noexcept;
[[nodiscard]] std::uint64_t invoke_text_driver(
    GuestMemory&, std::uint32_t entry, std::uint32_t self,
    std::uint64_t a1 = 0, std::uint64_t a2 = 0, std::uint64_t a3 = 0,
    ExecutionServices* services = nullptr, TextPresentationBackend* backend = nullptr);
}
