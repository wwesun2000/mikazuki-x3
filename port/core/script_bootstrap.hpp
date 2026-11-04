#pragma once
#include "script_image.hpp"
#include <array>
#include <optional>

namespace kx3 {
class ChoiceServices;

// A disk/file service owns a complete original ScenarioLink payload here.
// Resetting the optional consumes the one ready result for resource slot 3.
struct ReadyScenarioResource {
    std::vector<std::uint8_t> bytes;
    std::uint32_t completion_word;
};

struct ScriptBootstrapResult {
    ScriptImageIndex index{};
    std::uint32_t selector{}, label_id{}, entry_cursor{}, code_relative_offset{};
    std::uint32_t history{};
    std::array<std::uint32_t, 3> backups{};
    std::uint32_t registry{}, registration_index{}, registration_size{}, arena_used_end{};
};

// The caller reserves [arena_begin, arena_end) and supplies memory with the
// original ELF data, manager singleton and constructed normal-mode object at
// manager+20. The 1109D0 publication to manager+38 occurs at final commit.
// A failure leaves both RAM and the ready resource available to retry.
ScriptBootstrapResult bootstrap_script_data(GuestMemory&,
    std::optional<ReadyScenarioResource>& slot3, std::uint32_t arena_begin,
    std::uint32_t arena_end, ChoiceServices&);
}
