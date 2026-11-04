#pragma once
#include "guest_memory.hpp"

namespace kx3 {
struct SceneRegistryResult {
    std::uint32_t registry, file_base, cue_table, block_count, cue_count;
};
struct ReadySceneResource {
    std::uint32_t provider_storage, registry, file_base, cue_table, cue_capacity;
    std::span<const std::uint8_t> file;
};
std::uint32_t construct_scene_provider(GuestMemory&,std::uint32_t cold_storage);

// 101420 with a ready original slot-2 file and caller-reserved guest allocations.
// Publishes registry, relocated file and cue reverse index together. Can run
// inside the manager's transaction or independently.
SceneRegistryResult install_scene_registry(GuestMemory&, std::uint32_t registry, std::uint32_t file_base,
    std::span<const std::uint8_t> spk, std::uint32_t cue_table, std::uint32_t cue_capacity_bytes);

// 11DAC0 and 11DB60. The platform supplies a 32-byte allocation for a cold
// provider. A live provider retains its original address and vtable.
SceneRegistryResult activate_scene_provider(GuestMemory&, std::uint32_t cold_storage, std::uint32_t registry,
    std::uint32_t file_base, std::span<const std::uint8_t> spk, std::uint32_t cue_table,
    std::uint32_t cue_capacity_bytes);
}
