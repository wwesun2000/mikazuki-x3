#pragma once
#include "../../core/font_resource.hpp"
#include <filesystem>
#include <string_view>

namespace kx3::platform::windows {
FontResourceResult load_project_font(GuestMemory&,std::uint32_t descriptor,
                                     const std::filesystem::path& project,std::string_view program);
}
