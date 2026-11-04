#pragma once
#include <cstdint>
namespace kx3 {
class GuestMemory;
struct ExecutionServices;
[[nodiscard]] bool has_page_control(std::uint32_t entry) noexcept;
// Caller owns the guest transaction and access budget. Some source paths
// transfer labels, update recording callbacks or enter a waiting context.
[[nodiscard]] std::uint64_t invoke_page_control(GuestMemory&,std::uint32_t entry,
    std::uint32_t self,std::uint64_t a1=0,std::uint64_t a2=0,std::uint64_t a3=0,
    ExecutionServices* services=nullptr);
}
