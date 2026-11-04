#include "../platform/screen_transition.hpp"
#include <iostream>

int main(){
    using kx3::platform::RasterFrame;
    constexpr std::uint32_t task=0x1000,data=0x2000;
    kx3::GuestMemory ram;
    ram.write_u32(task+44,data);
    RasterFrame current{640,448,std::vector<std::uint8_t>(640*448*4,255)};
    for(unsigned f=0;f<2;++f){
        std::vector<std::uint8_t> field(640*224*4,std::uint8_t(32+f));
        auto p=0x100000+f*640*224*4;
        ram.write_u32(0x236114+4*f,p);ram.write_bytes(p,field);
    }
    for(unsigned y=0;y<448;++y)for(unsigned x=0;x<640;++x){
        auto k=(y*640+x)*4;current.rgba[k]=std::uint8_t(x);current.rgba[k+1]=std::uint8_t(y);
    }
    for(unsigned row=0;row<2;++row){
        const auto p=data+28*row;
        const std::array<float,6> xy=row?std::array<float,6>{4,4,0,4,0,4}:std::array<float,6>{0,4,0,0,0,4};
        for(unsigned j=0;j<xy.size();++j)ram.write_u32(p+8+4*j,std::bit_cast<std::uint32_t>(xy[j]));
    }
    for(unsigned count=0;count<=2;++count){
        if(count)ram.write_u32(data+28*(count-1)+32,1);
        auto result=current;
        kx3::platform::draw_screen_transition(result,ram,task);
        for(unsigned y=0;y<448;++y)for(unsigned x=0;x<640;++x){
            auto k=(y*640+x)*4;
            bool inside=(count==1 && x+y/2<4)||(count==2 && x<4 && y/2<4);
            for(unsigned c=0;c<4;++c)
                if(result.rgba[k+c]!=(inside?current.rgba[k+c]:std::uint8_t(32+y%2))){
                    std::cerr<<"Mismatch in triangle count "<<count<<" at "<<x<<","<<y<<" channel "<<c<<"\n";return 1;
                }
        }
    }
    std::cout<<"Passed saved field parity, disabled triangle, three left/top edges and shared diagonal at 640x448.\n";
}
