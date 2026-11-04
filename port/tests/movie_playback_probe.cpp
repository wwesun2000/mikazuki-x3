#include "../platform/windows/project_movie.hpp"
#include "../platform/windows/raster_loader.hpp"
#include "../platform/movie_catalog.hpp"
#include <iostream>

int main(int argc,char** argv) {
    using namespace kx3::platform;
    using namespace kx3::platform::windows;
    try {
        if(argc!=2)throw std::runtime_error("Expected original game project path");
        for(const auto& src:movie_bindings) {
            auto movie=prepare_original_movie(argv[1],src.name,src.size);
            for(unsigned member=0;member<movie->timing.size();++member) {
                for(unsigned frame=0;frame<movie->timing[member].frames;++frame) {
                    auto image=movie->load(member,frame);
                    std::cout<<"{\"movie\":\""<<src.name<<"\",\"member\":"<<member<<",\"frame\":"<<frame
                             <<",\"rgba_sha256\":\""<<source_bytes_sha256(image->rgba)<<"\"}\n";
                }
            }
            for(bool loop:{false,true}) {
                kx3::MoviePosition clock{.active=true,.loop=loop};
                // At 30 encoded frames/s and 60 host ticks/s the first frame
                // remains visible for two ticks. Compare every state crossing.
                std::uint32_t total=0;
                for(const auto& clip:movie->timing){
                    if(clip.fps_num!=30 || clip.fps_den!=1)throw std::runtime_error("Update clock expectations for this new clip rate");
                    total+=clip.frames;
                }
                for(std::uint32_t tick=0;tick<2*total+6;++tick) {
                    std::uint32_t index=tick/2,member=0;
                    bool playing=index<total || loop;
                    if(index>=total)index=loop?total-movie->timing.back().frames+
                        (index-total)%movie->timing.back().frames:total-1;
                    while(index>=movie->timing[member].frames)index-=movie->timing[member++].frames;
                    if(clock.member!=member || clock.frame!=index || clock.active!=playing)
                        throw std::runtime_error("MPEG/198158 frame clock disagree");
                    kx3::advance_movie_clock(clock,movie->timing);
                }
            }
        }
        return 0;
    } catch (const std::exception& e){std::cerr<<e.what()<<'\n';return 2;}
}
