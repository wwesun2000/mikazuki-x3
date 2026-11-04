#pragma once
#include "recovered.hpp"
#include <cstdint>
#include <span>
#include <vector>
#include <string>

namespace kx3 {
void install_name_entry(GuestMemory&,std::uint32_t manager,std::span<const std::uint8_t> namkan);
struct NameEntryCell {
    std::uint32_t index=0,column=0,row=0;
    std::string text_cp932;
    char source_kind=0; // Original row tag from 11BE28.
};
struct NameEntryView {
    bool open=false,confirming=false;
    std::uint32_t slot=0,page=0,focus=0,confirm_focus=0,max_chars=6;
    std::string draft_cp932;
    std::vector<NameEntryCell> cells;
};
NameEntryView name_entry_view(const GuestMemory&,std::uint32_t manager);
void retire_name_editor_tasks(GuestMemory&);
std::uint32_t name_task_payload(GuestMemory&,std::uint32_t task,std::uint32_t bytes);
bool point_at_answer_cell(GuestMemory&,std::uint32_t manager,int index);
bool has_name_entry(std::uint32_t);
std::uint64_t invoke_name_entry(GuestMemory&,std::uint32_t entry,std::uint32_t self,
                                std::uint64_t arg,ExecutionServices*);
}
