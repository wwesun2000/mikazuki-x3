#pragma once
#include <optional>
#include <cstdint>
#include <array>

namespace kx3 {
class GuestMemory;
std::optional<bool> context_input_predicate(const GuestMemory&,std::uint32_t manager,std::uint32_t method);
struct ExecutionServices;

[[nodiscard]] bool has_manager_input(std::uint32_t entry) noexcept;
[[nodiscard]] bool alternate_label_armed(const GuestMemory&,std::uint32_t manager);
void color_source_glyph_range(GuestMemory&,std::uint32_t channel,std::int32_t first,std::int32_t last,
                              const std::array<std::uint32_t,3>& rgb);
// Caller owns the guest transaction and access budget. An attached choice
// effect queue belongs to the same transaction. Physical button samples come
// from the original device records, including repeated reads in one update.
[[nodiscard]] std::uint64_t invoke_manager_input(
    GuestMemory&, std::uint32_t entry, std::uint32_t self,
    std::uint64_t a1 = 0, std::uint64_t a2 = 0, std::uint64_t a3 = 0,
    ExecutionServices* services = nullptr);
}
