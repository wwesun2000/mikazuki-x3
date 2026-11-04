#pragma once
#include "guest_memory.hpp"
#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace kx3 {
void copy_name13(GuestMemory&,std::uint32_t destination,std::uint32_t label);
std::uint8_t source_label_category(const GuestMemory&,std::uint32_t label);
std::uint8_t source_label_chapter(const GuestMemory&,std::uint32_t label);
enum class ChoiceEffectKind {
    glyph_color, glyph_step, glyph_current, pointer_move, pointer_hide,
    font_position, task_restore, task_retire, font_palette, task_callbacks, task_pause
};
struct ChoiceEffect {
    ChoiceEffectKind kind;
    std::uint32_t source_entry = 0;
    std::uint32_t channel = 0;
    std::int32_t first = 0, last_inclusive = -1;
    std::array<std::uint32_t, 3> rgb{};
    std::array<std::uint32_t, 3> secondary_rgb{};
    float value = 0, x = 0, y = 0;
    std::uint32_t guest_task = 0, guest_object = 0, callback = 0, secondary_callback = 0;
};
struct ChoiceInput {
    std::uint16_t edges = 0, held = 0;
    std::int32_t mouse_index = -1; // Modern adaptation: original option index.
    bool mouse_confirm = false;
    std::int32_t menu_index = -1; // Direct click on a row in the original system action table.
    bool menu_confirm = false;
    std::int32_t name_index = -1; // Current original page, absolute row*15+column.
    bool name_confirm = false;
    std::int32_t actor_index = -1; // Index in 14B2A0's four-card row.
    bool actor_confirm = false;
    bool original_card_menu = false; // Select the original card device instead of a PC snapshot.
};
struct ChoiceUpdate {
    std::uint64_t handler_return = 1;
    bool confirming = false, transferred = false, readback_entered = false;
    std::uint32_t focus = 0;
    std::vector<ChoiceEffect> pending_effects;
};

// Queries must reflect actual frontend state. Source calls may mutate only the
// supplied guest memory; external effects must remain deferred until commit.
// No default success implementations are provided for missing dependencies.
class ChoiceServices {
public:
    virtual ~ChoiceServices() = default;
    virtual bool supports_source(std::uint32_t entry) const = 0;
    virtual std::uint64_t call_source(GuestMemory&, std::uint32_t entry,
                                      std::span<const std::uint64_t> args) = 0;
    virtual bool supports_effect(ChoiceEffectKind) const = 0;
    virtual bool glyph_animation_pending() const = 0;
};

// Source 11E748 / 11E608 context slice, called AFTER manager pre-input gates.
// Ordinary mode1 only: scripted sequence/autoplay/special contexts fail clearly.
// Owns a guest transaction; do not call inside an existing transaction. Returned
// effects are published only after commit, and must be applied before next tick.
ChoiceUpdate choice_context_atomic(GuestMemory&, std::uint32_t manager,
                                   const ChoiceInput&, ChoiceServices&);

// Source10D868 with10ECA0(a2=0),19CB50 and10F198. Requires a caller-owned
// transaction/access budget. Source selector/label names and all history state
// remain in GuestMemory; callbacks use the same explicit service boundary.
void choice_transfer_transactional(GuestMemory&, std::uint32_t script,
                                   std::uint64_t selector, std::uint32_t label,
                                   std::uint64_t flag, ChoiceServices&);

// Original19CB50 shared by ordinary transfers and page-end visits.
// Requires the caller-owned guest transaction and access budget.
void choice_progress_label_transactional(GuestMemory&, std::uint32_t label,
                                         ChoiceServices&);
void choice_begin_label_transactional(GuestMemory&,std::uint32_t label,
                                      std::uint64_t readback,ChoiceServices&);
bool source_choice_option_read(GuestMemory&,std::uint32_t manager,std::uint32_t choice,std::uint32_t index);
// 19C868: slot zero receives both the source label and entry reason.
void page_progress_label_transactional(GuestMemory&, std::uint32_t label,
                                       std::uint64_t reason, ChoiceServices&);

// Integration variant for a root VM step that already owns the transaction and
// access budget. Do not publish pending_effects until that outer step commits.
ChoiceUpdate choice_context_transactional(GuestMemory&, std::uint32_t manager,
                                          const ChoiceInput&, ChoiceServices&);

// Source1173A8 gate. Root's full112F78 manager pre-input should call this before
// the context slice. Uses actual helper predicates and1165D8 readback execution;
// unsupported callbacks fail, never silently turn Up@A into normal navigation.
ChoiceUpdate choice_readback_gate_atomic(GuestMemory&, std::uint32_t manager,
                                        const ChoiceInput&, ChoiceServices&);
ChoiceUpdate choice_readback_gate_transactional(GuestMemory&, std::uint32_t manager,
                                               const ChoiceInput&, ChoiceServices&);

// Source15F168 edge cache on an already selected input-device record. Host input
// collection supplies +B8 and marks +B4; repeated reads preserve the same edges.
std::uint16_t choice_device_edges(GuestMemory&, std::uint32_t input_device);

// Original134AF0 (also reached by134BD0): actual manager/global eligibility
// fields and current history record. This does not execute readback itself.
bool choice_readback_eligible(GuestMemory&);

// Original1165D8 ordinary backward entry(mode0). Returns the actual gate result
// and deferred source-semantic presentation changes. Other modes require their
// original lookahead closure and fail explicitly until recovered.
ChoiceUpdate choice_readback_begin_transactional(GuestMemory&, std::uint32_t helper,
                                                std::uint32_t manager,
                                                std::uint64_t selector,
                                                std::uint64_t label_id,
                                                std::uint64_t mode,
                                                ChoiceServices&);
}
