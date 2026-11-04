#pragma once
#include "guest_memory.hpp"
#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace kx3 {
struct SaveIdentity {
    std::array<std::uint8_t, 32> executable_sha256{};
    std::array<std::uint8_t, 32> assets_sha256{};
    std::uint32_t core_abi_revision = 1;
    bool operator==(const SaveIdentity&) const = default;
};
struct CoreCheckpoint {
    GuestMemory memory;
    std::uint32_t manager = 0;
    std::uint64_t logical_tick = 0;
};
// Stores all guest RAM fields, including histories/variables/pending choices.
// Presentation/audio continuation state must be added to the session container
// before this core checkpoint can be advertised as a complete playable save.
std::vector<std::uint8_t> encode_checkpoint(const CoreCheckpoint&, const SaveIdentity&);
CoreCheckpoint decode_checkpoint(std::span<const std::uint8_t>, const SaveIdentity&);
// Same-directory, flushed temporary file + atomic replacement. Existing slot
// remains intact on preparation/validation errors. Does not write user profiles.
void write_checkpoint_atomic(const std::filesystem::path&, const CoreCheckpoint&, const SaveIdentity&);
void replace_save_file_atomic(const std::filesystem::path&, std::span<const std::uint8_t>,
                              bool independent_temporary=true);
CoreCheckpoint read_checkpoint(const std::filesystem::path&, const SaveIdentity&);
}
