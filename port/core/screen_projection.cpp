#include "screen_projection.hpp"
#include "guest_memory.hpp"
#include <bit>
#include <cmath>
#include <stdexcept>

#pragma STDC FP_CONTRACT OFF

namespace kx3 {
namespace {
using Vec=std::array<float,4>;
using Matrix=std::array<Vec,4>; // 1C1590 stores four column vectors.
float number(const GuestMemory& memory,std::uint32_t address){
    return std::bit_cast<float>(memory.read_u32(address));
}
Matrix identity(){
    return {{{1,0,0,0},{0,1,0,0},{0,0,1,0},{0,0,0,1}}}; // 1C1888
}
Vec transform(const Matrix& matrix,const Vec& point){
    Vec out{};
    for(unsigned i=0;i<4;++i){
        float acc=matrix[0][i]*point[0];
        acc+=matrix[1][i]*point[1];acc+=matrix[2][i]*point[2];acc+=matrix[3][i]*point[3];
        out[i]=acc;
    }
    return out;
}
Matrix product(const Matrix& a,const Matrix& b){
    return {transform(a,b[0]),transform(a,b[1]),transform(a,b[2]),transform(a,b[3])};
}
Matrix rotation(const GuestMemory& m,float angle){
    // 1C1928 → 1C18B0. The VU constructs cos(theta) as a polynomial in
    // pi/2-|theta|, then computes the signed sine from its complement.
    const float half_pi=std::bit_cast<float>(0x3fc90fdbu);
    const float arg=angle<0?half_pi+angle:half_pi-angle;
    const float squared=arg*arg;
    Vec term{};
    for(unsigned i=0;i<4;++i)term[i]=number(m,0x211ef0+i*4)*arg;
    float cosine=arg;
    for(unsigned n=4;n;--n){
        for(unsigned i=0;i<n;++i)term[i]*=squared;
        cosine+=term[n-1];
    }
    // VU SQRT takes the magnitude of a negative radicand and sets status.
    const float root=std::sqrt(std::abs(1.f-cosine*cosine));
    const float sine=angle<0?-root:root;
    return {{{cosine,sine,0,0},{-sine,cosine,0,0},{0,0,1,0},{0,0,0,1}}};
}
}

std::array<float,2> clip_screen_point(const GuestMemory& m,std::array<float,2> p){
    const float cx=number(m,0x237d5c),cy=number(m,0x237d60);
    const float bottom=number(m,0x237d6c),right=number(m,0x237d70);
    auto& [x,y]=p;
    if(y<0){x=(x-cx)*number(m,0x237d68)/(y-cy)+cx;y=0;}
    if(y>bottom){x=cx+(x-cx)*(bottom-cy)/(y-cy);y=bottom;}
    if(x<0){y=cy+(y-cy)*(0.f-cx)/(x-cx);x=0;}
    if(x>right){y=cy+(y-cy)*(right-cx)/(x-cx);x=right;}
    return p;
}

std::array<float,2> screen_project_point(GuestMemory& m,float angle){
    if(angle==0)return clip_screen_point(m,{number(m,0x237d9c),number(m,0x237da0)});
    // The sole FOV operand is an original read-only literal. 1F08F0
    // returns these bits after 183 original R5900 instructions.
    if(m.read_u32(0x237d74)!=0x3f860a92u)throw std::runtime_error("1925F8: unexpected original projection FOV");
    const float tangent=std::bit_cast<float>(0x3fddb3d8u);
    const float distance=number(m,0x237d88)/(tangent+tangent);
    const float near=number(m,0x237d84),far=number(m,0x237da4),zmax=number(m,0x237d80);
    // 1C1D70: perspective and screen adjustment matrices in guest order.
    Matrix perspective={{{distance,0,0,0},{0,distance,0,0},{0,0,0,1},{0,0,1,0}}};
    Matrix adjust=identity();
    adjust[0][0]=near;adjust[1][1]=number(m,0x237d7c);
    adjust[2][2]=(far*near*zmax)/(-near+far);
    adjust[3]={number(m,0x237d78),number(m,0x237d78),(-zmax*near)/(-near+far),1};
    auto translation=identity();translation[3][2]+=distance; // 1C17E0
    const auto matrix=product(product(product(adjust,perspective),translation),rotation(m,angle));
    // 17AD38 installs the matrix in VF1..4. 17ADB8 writes a temporary
    // homogeneous Vec4, of which all four drawing paths consume only xy.
    Vec point=transform(matrix,{number(m,0x237d8c),number(m,0x237d90),0,near});
    const float reciprocal=1.f/point[3];
    return clip_screen_point(m,{point[0]*reciprocal-number(m,0x237da8),point[1]*reciprocal-number(m,0x237dac)});
}

std::uint32_t screen_sector_for_y(const GuestMemory& m,float angle,float y){
    const auto bottom=number(m,0x237db0);
    if(angle>0){
        if(!(y>0))return 0;
        return y<bottom?1:2;
    }
    if(!(y<bottom))return 3;
    return y>0?4:5;
}
std::uint32_t screen_project_sector(GuestMemory& m,float angle){
    return screen_sector_for_y(m,angle,screen_project_point(m,angle)[1]);
}
}
