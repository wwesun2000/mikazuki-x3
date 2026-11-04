#pragma once
#include "../core/guest_memory.hpp"
#include <filesystem>
namespace kx3::tests {
void run_story_frames(GuestMemory&,const std::filesystem::path& project_root,bool choice_scene,const std::filesystem::path& test_save);
}
