#pragma once
#include "../core/text_driver.hpp"
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kx3 { class GuestMemory; }
namespace kx3::platform {
enum class StoryLanguage : unsigned { japanese, chinese, english };
struct LocalizedLine {
    bool operator==(const LocalizedLine&) const = default;
    std::string group_id, text;
    int x=0, y=0, height=0;
    unsigned primary_units=0, total_primary=0;
    std::uint32_t first_node=0;
    unsigned opacity=0; // Maximum visible opacity of this group's primary nodes, 0..255.
    int option=-1;
    unsigned rgb=0xffffff; // Live GS modulation of a white host-font glyph.
    bool player_name_cp932=false; // Inline slot text in CP932 (ASCII aliases are valid CP932).
    std::uint32_t insertion_offset=0; // Original ScenarioLink name opcode supplying this line.
};
struct LocalizedPage {
    std::vector<LocalizedLine> lines;
    // Stable source IDs for records without an available target. Runtime
    // template addresses are identified separately from retail file offsets.
    std::vector<std::string> pending;
};
LocalizedPage localize_story_page(const GuestMemory&,std::uint32_t script,StoryLanguage,
                                  std::span<const TextGlyphEvent> committed,std::string_view scenario="sn4g");
std::string_view english_default_player_name(unsigned slot,std::string_view full_cp932);
std::string_view localize_chart_title(std::string_view table,unsigned index,
                                      std::string_view unlocked_cp932,StoryLanguage);
}
