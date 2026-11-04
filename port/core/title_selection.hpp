#pragma once
#include "guest_memory.hpp"
#include <array>
#include <string>

namespace kx3 {
struct TitleEdition { unsigned mode=0;std::string program; };
struct TitleSelection {
    std::array<TitleEdition,3> rows;
    unsigned focus=0;
    bool load=false;
};
enum class TitleAction { idle,accept,back };
struct ExecutionServices;
TitleAction advance_title_selection(GuestMemory&,TitleSelection&,std::uint16_t pressed,ExecutionServices&);
// 108B40 / 109DE8. The normal and Continue pages have separate ELF tables.
TitleSelection source_title_selection(const GuestMemory&,bool load);
}
