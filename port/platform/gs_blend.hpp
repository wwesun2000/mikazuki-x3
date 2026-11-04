#pragma once

namespace kx3::platform {
// GS ALPHA=0x44 uses seven fractional bits. FOG uses eight. Both keep
// the signed high part of a channel difference before the final addition.
constexpr int source_over_channel(int source,int destination,int alpha) noexcept {
    return destination+(((source-destination)*alpha)>>7);
}
constexpr int fog_channel(int texel,int fog,int factor) noexcept {
    return fog+(((texel-fog)*factor)>>8);
}
}
