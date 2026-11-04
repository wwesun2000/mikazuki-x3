#pragma once
#include "guest_memory.hpp"
#include <span>
#include <string>

namespace kx3 {
struct SabFileInfo {
    std::uint32_t header,frames,color_palette,mask_palettes,colorshift;
};
struct SabLayer {
    std::uint32_t colors,mask,mask_palette,x,y,width,height,color_width,color_height,mask_width,mask_height;
};
// The eight originals all contain one layer per frame. Other encodings are
// reported at the original parser/draw boundary instead of being displayed.
SabFileInfo inspect_sab_file(std::span<const std::uint8_t>);
SabLayer inspect_sab_layer(std::span<const std::uint8_t>,const SabFileInfo&,std::uint32_t frame);
struct SabBlob { std::string name;std::span<const std::uint8_t> bytes; };
void install_sab_files(GuestMemory&,std::span<const SabBlob>);
std::uint32_t find_sab_file(const GuestMemory&,std::uint32_t filename);
std::uint64_t invoke_sab_animation(GuestMemory&,std::uint32_t entry,std::uint32_t object,
                                   std::uint32_t arg1=0,std::uint32_t arg2=0);
void advance_sab_draw(GuestMemory&); // 1354C8..1354FC; stores the original submitted frame for native display.
struct SabDisplay { std::span<const std::uint8_t> bytes;std::uint32_t frame; };
SabDisplay visible_sab(const GuestMemory&);
}
