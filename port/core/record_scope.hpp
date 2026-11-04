#pragma once
#include "recovered.hpp"

namespace kx3 {
bool has_record_scope(std::uint32_t entry) noexcept;
std::uint64_t invoke_record_scope(GuestMemory&,std::uint32_t entry,std::uint32_t self,std::uint64_t a1);
}
