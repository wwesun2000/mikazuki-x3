#pragma once
#include "recovered.hpp"
#include <array>

namespace kx3 {
// 14B2A0 renders these four records from PANEL/hrsel.dat in source order.
struct ActorChoiceView {
    bool open=false, accepting=false;
    unsigned focus=0, opacity=0;
    std::array<unsigned,4> portrait{},highlight{};
};
ActorChoiceView actor_choice_view(const GuestMemory&,std::uint32_t manager);
void advance_actor_panel(GuestMemory&,ExecutionServices*);
bool has_actor_choice(std::uint32_t);
std::uint64_t invoke_actor_choice(GuestMemory&,std::uint32_t entry,std::uint32_t self,
                                  std::uint64_t a1,ExecutionServices*);
}
