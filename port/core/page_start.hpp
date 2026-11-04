#pragma once
#include "recovered.hpp"

namespace kx3 {
bool has_page_start(std::uint32_t entry) noexcept;
std::uint64_t invoke_page_start(GuestMemory&, std::uint32_t entry, std::uint32_t self,
                                std::uint64_t a1, ExecutionServices*);
}
