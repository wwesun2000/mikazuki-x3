#pragma once
#include "script_bootstrap.hpp"

namespace kx3 {
struct ReadySceneResource;
struct ColdDispatchRuntime {
    std::uint32_t manager{}, default_context{}, constructed_handlers{}, null_handlers{};
    std::uint32_t registry{}, manager_arena_used_end{};
    ScriptBootstrapResult script;
};
void restore_missing_panel_modes(GuestMemory&,std::uint32_t manager);
// On legacy load only, recover original singleton/choice task fields that were
// absent in earlier builds. The last 128 bytes in the 2 KiB reserve restore
// 116370's single-entry format stack for save versions which lacked it.
void restore_missing_choice_bootstrap(GuestMemory&,std::uint32_t manager,
                                      std::uint32_t reserve_begin,std::uint32_t reserve_end);

// Constructs the evidenced source manager/dispatch and ScriptData slice.
// The two caller-reserved arenas and the slot-4 font image must be disjoint.
ColdDispatchRuntime bootstrap_manager_dispatch(GuestMemory&, std::optional<ReadyScenarioResource>& slot3,
    std::uint32_t manager_begin, std::uint32_t manager_end, std::uint32_t script_begin,
    std::uint32_t script_end, ChoiceServices&, std::span<const std::uint8_t> font_file,
    std::uint32_t font_descriptor,const ReadySceneResource* slot2=nullptr);
}
