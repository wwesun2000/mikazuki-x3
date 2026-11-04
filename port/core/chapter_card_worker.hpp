#pragma once
#include <cstdint>
namespace kx3 {
class GuestMemory;
class CardVolume;
void advance_card_thread(GuestMemory&,CardVolume&,std::uint32_t entry);
}
