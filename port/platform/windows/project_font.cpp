#include "project_font.hpp"
#include "raster_loader.hpp"

namespace kx3::platform::windows {
FontResourceResult load_project_font(GuestMemory& memory,std::uint32_t descriptor,
                                     const std::filesystem::path& project,std::string_view program) {
    struct FontFile {std::string_view program;const char* filename;std::uint64_t bytes;const char* sha256;};
    constexpr FontFile files[]{
        {"sn2","sn2.fnt",879364,"396d03ea918799696e06495813c0369c8059b18c1ddf1e74b4d1595b4bb84738"},
        {"sn4","sn4.fnt",1349780,"a3dac7e146cc970e4c8ae2c191afa4ffd2592765c0f11e300a66b7ddf12d00c7"},
        {"sn4g","sn4g.fnt",1098219,"c12f602b3716b1dce68d6bdbcb58b45dbe29d67dab0a5ef7dbb35210e3d370b3"}
    };
    for(const auto& file:files) {
        if(file.program!=program)continue;
        const auto encoded=read_disc_resource(project,std::string("SCENARIO/")+file.filename,file.sha256,file.bytes);
        return install_font_resource(memory,descriptor,encoded);
    }
    throw std::invalid_argument("Unknown original scenario font");
}
}
