#pragma once
#include <cstdint>
namespace kx3 {
class GuestMemory;
float source_pitch_multiplier(const GuestMemory&,std::int32_t cents);
unsigned source_pitch_register(unsigned base,float multiplier);
unsigned source_pan_index(float normalized);
unsigned source_volume_register(unsigned base,float left,float right);
struct SoundPitch {
    float current=1,step=0,target=1;
    void set(float multiplier,std::uint32_t ticks);
    void advance();
};
}
