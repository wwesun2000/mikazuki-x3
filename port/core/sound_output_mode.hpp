#pragma once
#include <cstdint>
#include "audio_worker.hpp"
namespace kx3 {
class GuestMemory;
// Source 1B0ED0 enqueues. 1B0370 consumes it on the sound worker.
void enqueue_sound_output_mode(GuestMemory&,std::uint32_t enabled);
std::uint32_t allocate_sound_packet(GuestMemory&,std::uint32_t command);
void submit_sound_packet(GuestMemory&,std::uint32_t packet);
std::vector<SourceSoundEvent> service_sound_packets(GuestMemory&);
}
