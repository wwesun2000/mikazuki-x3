#include "mime_effect.hpp"
#include "cue_effect.hpp"
#include "session_clock.hpp"
#include <bit>
#include <cmath>
#include <algorithm>

namespace kx3 {
namespace {
using u32=std::uint32_t;using i32=std::int32_t;
float f(const GuestMemory& m,u32 p){return std::bit_cast<float>(m.read_u32(p));}
void put(GuestMemory& m,u32 p,float x){m.write_u32(p,std::bit_cast<u32>(x));}
i32 integer(u32 n){return std::bit_cast<i32>(n);}
float divide_by_ticks(float numer,i32 ticks){
    // EE DIV.S, as in PCSX2 2.8.2 FPU.cpp checkDivideByZero. The one
    // my0215_20 zero-speed create is followed by CHANGE before a draw.
    if(!ticks)return std::copysign(std::bit_cast<float>(0x7f7fffffu),numer);
    return numer/float(ticks);
}
u32 pool(const GuestMemory& m,u32 task){
    const auto first=m.read_u32(0x2388bc)+13*48;
    if(task<first || task>=first+480 || (task-first)%48)throw std::runtime_error("17BA58 invalid mesh task");
    return 0x1410000+((task-first)/48)*0x16000;
}
// 1F0838. The registered 17BA58 mesh's stored phase always stays in [-pi,pi].
float phase_sine(const GuestMemory& m,float x){
    const auto bits=std::bit_cast<u32>(x),ab=bits&0x7fffffff;
    if(ab>0x40490fdb)throw std::runtime_error("1F0838 mesh phase outside bounded source reduction");
    auto sine=[&](float a,float tail,bool reduced){
        if((std::bit_cast<u32>(a)&0x7fffffff)<0x32000000)return a;
        const float z=a*a,v=z*a;
        float poly=f(m,0x234e34);
        for(u32 p=0x234e38;p<=0x234e44;p+=4)poly=z*poly+f(m,p);
        return reduced?a-((z*(tail*f(m,0x234e4c)-v*poly)-tail)-v*f(m,0x234e48)):
                       a+v*(z*poly+f(m,0x234e48));
    };
    auto cosine=[&](float a,float tail){
        const u32 ix=std::bit_cast<u32>(a)&0x7fffffff;
        if(ix<0x32000000)return f(m,0x234d8c);
        const float z=a*a;float p=f(m,0x234d90);
        for(u32 addr=0x234d94;addr<=0x234da4;addr+=4)p=z*p+f(m,addr);
        const float corr=z*(z*p)-a*tail,half=f(m,0x234da8);
        if(ix<0x3e99999a)return f(m,0x234d8c)-(z*half-corr);
        const float q=ix<0x3f480001?std::bit_cast<float>(ix-0x1000000):0.28125f;
        return (f(m,0x234d8c)-q)-((z*half-q)-corr);
    };
    if(ab<0x3f490fd9)return sine(x,0,false);
    const float a=std::abs(x);float first=0,tail=0;int quadrant=1;
    if(ab<0x4016cbe4){
        float t=a-f(m,0x234bf8),small=f(m,0x234bfc);
        if((ab&0x7ffffff0)==0x3fc90fd0){t-=f(m,0x234c04);small=f(m,0x234c00);}
        first=t-small;tail=(t-first)-small;
    }else{
        quadrant=int(a*f(m,0x234c08)+f(m,0x234c0c));const auto n=float(quadrant);
        float t=a-n*f(m,0x234bf8),w=n*f(m,0x234bfc);
        first=t-w;
        if((ab&0x7fffff00)==m.read_u32(0x234b4c+4*quadrant)){
            const auto exp=[](float x){return int((std::bit_cast<u32>(x)>>23)&255);};
            for(auto parts:{std::array<u32,3>{8,0x234c04,0x234c00},{25,0x234c10,0x234c14}}){
                if(exp(a)-exp(first)<=int(parts[0]))break;
                const float part=n*f(m,parts[1]),next=t-part;
                w=n*f(m,parts[2])-((t-next)-part);t=next;first=t-w;
            }
        }
        tail=(t-first)-w;
    }
    if(bits>>31){first=-first;tail=-tail;quadrant=-quadrant;}
    switch(quadrant&3){case 0:return sine(first,tail,true);case 1:return cosine(first,tail);
        case 2:return -sine(first,tail,true);default:return -cosine(first,tail);}
}
}
u32 mime_grid(const GuestMemory& m,u32 task){
    const auto data=m.read_u32(task+44);
    if(data!=pool(m,task) || m.read_u32(data)!=10 || m.read_u32(data+4)!=10 || m.read_u32(data+84)!=data+128)
        throw std::runtime_error("17C698 invalid original mesh allocation");
    return data+128;
}
u32 create_mime_effect(GuestMemory& m,std::span<const u32> a,ExecutionServices* services){
    if(a.size()!=5)throw std::runtime_error("17BA58 invalid original effect arguments");
    const auto task=reserve_mode_zero_task(m),data=pool(m,task),grid=data+128;
    m.write_u32(task+20,0x17c498);m.write_u32(task+24,0x17c698);m.write_u32(task+28,0x17c960);
    m.write_u32(task+32,0x17ca80);m.write_u32(task+44,data);
    m.write_u32(data,10);m.write_u32(data+4,10);m.write_u32(data+84,grid);
    const float dx=640.f/9,dy=224.f/9,n=float(integer(a[0]?a[0]:1));
    put(m,data+8,dx);put(m,data+12,dy);m.write_u32(data+52,a[0]?a[0]:1);
    for(unsigned c=0;c<3;++c){
        put(m,data+16+4*c,f(m,0x2372e8));put(m,data+28+4*c,float(integer(a[1+c])));
        put(m,data+40+4*c,float(integer(a[c+1]-128))/n);
    }
    put(m,data+56,divide_by_ticks(f(m,0x2372e4),integer(a[4])));m.write_u32(data+60,10);m.write_u32(data+64,0);
    float y=0;
    for(unsigned row=0;row<10;++row,y+=dy){
        float x=0;
        for(unsigned col=0;col<10;++col,x+=dx){
            const auto p=grid+36*(10*row+col);
            const float angle=source_random_range(m,0,f(m,0x2372f8),services);
            put(m,p,x);put(m,p+4,y);put(m,p+8,x);put(m,p+12,y);put(m,p+24,angle);
            const float sign=(row && col && row<9 && col<9)?phase_sine(m,angle):0;
            put(m,p+16,x+sign*(dx*f(m,0x2372ec)));put(m,p+20,y+sign*(dy*f(m,0x2372ec)));
            put(m,p+28,x*f(m,0x2372f0));put(m,p+32,y*f(m,0x2372f4));
        }
    }
    m.write_u32(data+68,0);return task;
}
void change_mime_effect(GuestMemory& m,u32 task,std::span<const u32> a){
    if(a.size()!=5)throw std::runtime_error("17C960 invalid mesh change arguments");
    (void)mime_grid(m,task);const auto data=m.read_u32(task+44);
    m.write_u32(data+52,a[0]);
    for(unsigned c=0;c<3;++c){
        const auto target=float(integer(a[c+1]));put(m,data+28+4*c,target);
        put(m,data+40+4*c,divide_by_ticks(target-f(m,data+16+4*c),integer(a[0])));
    }
    put(m,data+56,a[4]?f(m,0x237320)/float(integer(a[4])):f(m,0x237320));
    m.write_u32(task+16,0);m.write_u32(task+20,a[4]?0x17c498:0x17c598);
}
void update_mime_effect(GuestMemory& m,u32 task,ExecutionServices* services){
    const auto grid=mime_grid(m,task),data=m.read_u32(task+44),left=m.read_u32(data+52);
    if(integer(left)>0){
        for(unsigned c=0;c<3;++c){
            const float target=f(m,data+28+4*c),step=f(m,data+40+4*c),next=f(m,data+16+4*c)+step;
            put(m,data+16+4*c,step<0?std::max(next,target):std::min(next,target));
        }
    }
    m.write_u32(data+52,integer(left-1)>0?left-1:0);if(integer(left-1)<=0)m.write_u32(task+16,1);
    const bool restore=m.read_u32(task+20)==0x17c598;
    if(!restore){
        const auto tick=m.read_u32(data+64)+1;
        const bool renew=integer(tick)>=integer(m.read_u32(data+60));m.write_u32(data+64,renew?0:tick);
        if(renew){
            if(m.read_u32(data+68))throw std::runtime_error("17C31C radial mesh behavior unavailable");
            for(unsigned y=1;y<9;++y)for(unsigned x=1;x<9;++x){
                const auto p=grid+36*(10*y+x);
                const float delta=source_random_range(m,0,1,services)*f(m,0x237308)+f(m,0x23730c);
                float angle=f(m,p+24)+delta;if(angle>f(m,0x2372fc))angle-=f(m,0x237300);
                put(m,p+24,angle);const float v=phase_sine(m,angle);
                put(m,p+16,f(m,p)+v*(f(m,data+8)*f(m,0x237304)));
                put(m,p+20,f(m,p+4)+v*(f(m,data+12)*f(m,0x237304)));
            }
        }
    }
    const float factor=restore?f(m,0x237314):f(m,data+56);
    for(unsigned y=0;y<9;++y)for(unsigned x=0;x<9;++x){
        const auto p=grid+36*(10*y+x);
        for(unsigned off:{0u,4u}){float now=f(m,p+8+off);put(m,p+8+off,now+(f(m,p+(restore?0:16)+off)-now)*factor);}
    }
}
}
