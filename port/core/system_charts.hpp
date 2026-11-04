#pragma once
#include "guest_memory.hpp"
#include <array>
#include <utility>
#include <span>
#include <string>
#include <vector>

namespace kx3 {
// Source file slot 5 handed to 1AB330. The caller supplies a reserved heap
// interval for the original DAT bytes; the source's pointer table lives in RAM.
void install_ending_list(GuestMemory&, std::uint32_t guest_base, std::span<const std::uint8_t> bytes);
std::uint32_t consume_source_ending_list(GuestMemory&); // 1AB330, caller-owned transaction.
struct EndingListEntry {
    bool reached=false;
    std::string title_cp932;  // Available only after original 1AB578 unlock.
    bool replay_prompt=false; // 1AB5E8 special result; does not set the ending record bit.
};
bool can_replay_ending(const GuestMemory&,std::uint32_t index);
std::vector<EndingListEntry> ending_list_entries(const GuestMemory&);
struct ChapterFileStorage { std::uint32_t records, textures, work; };
void install_chapter_list(GuestMemory&, ChapterFileStorage,
                         std::span<const std::uint8_t> records,std::span<const std::uint8_t> textures);
void prepare_chapter_menu(GuestMemory&); // Source 1AF6E0 uses player progress bits.
void update_chapter_progress(GuestMemory&,std::uint32_t label,std::uint64_t reason);
// 1AC108 and 1ADB48 receive slot 6 and four heap allocations. The workspace
// contains the original TIM bytes, pointer table, progress bits, both chart
// matrices and the 32-byte chart viewer, in that order at aligned addresses.
void install_time_chart(GuestMemory&,std::uint32_t arena,std::uint32_t capacity,
                        std::span<const std::uint8_t> data);
void update_time_chart_progress(GuestMemory&,std::uint32_t label);
struct TimeChartCell {
    std::uint32_t time_row=0,actor=0,title_id=0;
    std::string title_cp932;
};
struct TimeChartView {
    std::uint32_t row=0,actor=0,first_row=0;
    std::array<std::string,4> actors_cp932;
    std::vector<std::pair<std::int32_t,std::uint32_t>> times;
    std::vector<TimeChartCell> available_cells;
};
TimeChartView visible_time_chart(const GuestMemory&);
struct ChapterRow {std::uint32_t source_id=0;std::string title_cp932;std::uint32_t number=0;};
struct ChapterView {std::uint32_t first=0;std::vector<ChapterRow> rows;};
ChapterView visible_chapter_list(const GuestMemory&);
std::uint32_t mark_source_ending(GuestMemory&,std::uint32_t label);
}
