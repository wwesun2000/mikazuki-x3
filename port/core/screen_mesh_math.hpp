#pragma once
// VU host boundary for effect/wipe_crash.c; original39-case comparison in screen-mesh-92/sol/rev2.
// Original leaves: 1C1590,1C1620,1C17E0,1C1888,1C1928,1C19D0,
// 1C1A78,1C1D70,17AD38,17AD50. Exceptional VU input domains are not admitted.
#include "ee_scalar.hpp"
#include <array>
#include <bit>
#include <cmath>
#include <stdexcept>
namespace kx3::screen_mesh {
using Vec=std::array<float,4>;
using Matrix=std::array<Vec,4>; // Guest column-major, exactly as 1C1590.
// VU operations use their own round-toward-zero domain, separate from EE
// scalar one-guard-bit ADD/SUB and the original EE DIV mode. Do not change
// process-wide FP state: audio, UI and other recovered routines share it.
inline float vu_add(float a,float b){return ee::round_towards_zero(double(a)+double(b));}
inline float vu_mul(float a,float b){return ee::round_towards_zero(double(a)*double(b));}
inline float vu_div(float a,float b){return ee::round_towards_zero(double(a)/double(b));}
inline float vu_sqrt(float a){return ee::round_towards_zero(std::sqrt(std::abs(double(a))));}
inline Matrix identity(){return {{{1,0,0,0},{0,1,0,0},{0,0,1,0},{0,0,0,1}}};}
inline Vec transform(const Matrix& matrix,const Vec& v){
    Vec out{};
    for(unsigned i=0;i<4;++i){
        float acc=vu_mul(matrix[0][i],v[0]);
        acc=vu_add(acc,vu_mul(matrix[1][i],v[1]));acc=vu_add(acc,vu_mul(matrix[2][i],v[2]));
        out[i]=vu_add(acc,vu_mul(matrix[3][i],v[3]));
    }
    return out;
}
inline Matrix product(const Matrix& a,const Matrix& b){
    return {transform(a,b[0]),transform(a,b[1]),transform(a,b[2]),transform(a,b[3])};
}
inline Vec normalized(const Vec& input){ // 1C1620 clears w and normalizes xyz.
    float norm=vu_mul(input[0],input[0]);
    norm=vu_add(norm,vu_mul(input[1],input[1]));norm=vu_add(norm,vu_mul(input[2],input[2]));
    const float length=vu_sqrt(norm);
    if(!std::isfinite(length) || length==0)throw std::runtime_error("1C1620 unsupported zero/nonfinite vector");
    const float q=vu_div(1.f,length);
    return {vu_mul(input[0],q),vu_mul(input[1],q),vu_mul(input[2],q),0};
}
inline Matrix translated(Matrix m,const Vec& v){ // 1C17E0 does not transform v.
    for(unsigned i=0;i<3;++i)m[3][i]=vu_add(m[3][i],v[i]);
    return m;
}
inline Matrix rotation(float angle,unsigned axis,const Vec& coefficients){
    if(axis>2 || !std::isfinite(angle))throw std::runtime_error("Invalid original rotation input");
    // FPU prefix of 1C1928/19D0/1A78, before the common VU polynomial1C18B0.
    const float half_pi=std::bit_cast<float>(0x3fc90fdbu);
    const float arg=ee::ee_add_sub(half_pi,angle,angle>=0);
    const float square=vu_mul(arg,arg);
    Vec term{};for(unsigned i=0;i<4;++i)term[i]=vu_mul(coefficients[i],arg);
    float cosine=arg;
    for(unsigned n=4;n;--n){for(unsigned i=0;i<n;++i)term[i]=vu_mul(term[i],square);cosine=vu_add(cosine,term[n-1]);}
    const float root=vu_sqrt(vu_add(1.f,-vu_mul(cosine,cosine)));
    const float sine=angle<0?-root:root;
    // Exact column assembly after1C18B0. Callers pre-multiply the input matrix.
    if(axis==0)return {{{1,0,0,0},{0,cosine,sine,0},{0,-sine,cosine,0},{0,0,0,1}}};
    if(axis==1)return {{{cosine,0,-sine,0},{0,1,0,0},{sine,0,cosine,0},{0,0,0,1}}};
    return {{{cosine,sine,0,0},{-sine,cosine,0,0},{0,0,1,0},{0,0,0,1}}};
}
inline Matrix projection(const std::array<float,9>& args){
    // 1C1D70 f12..f19 plus incoming stack+0. Scalar operations retain EE order.
    const auto add=[](float a,float b){return ee::ee_add_sub(a,b,false);};
    const auto mul=[](float a,float b){return ee::round_towards_zero(double(a)*double(b));};
    const float difference=add(-args[5],args[6]);
    float scale=mul(args[8],args[7]);scale=mul(scale,difference);
    float offset=add(mul(-args[6],args[7]),mul(args[5],args[8]));
    const float divisor=add(-args[7],args[8]);
    if(divisor==0)throw std::runtime_error("1C1D70 projection divisor is zero");
    scale/=divisor;offset/=divisor;
    Matrix perspective=identity();
    perspective[0][0]=args[0];perspective[1][1]=args[0];
    perspective[2][2]=0;perspective[3][3]=0;perspective[2][3]=1;perspective[3][2]=1;
    Matrix adjust=identity();
    adjust[0][0]=args[1];adjust[1][1]=args[2];adjust[2][2]=scale;
    adjust[3][0]=args[3];adjust[3][1]=args[4];adjust[3][2]=offset;
    return product(adjust,perspective);
}
inline std::array<std::int32_t,4> projected_fixed4(const Matrix& m,const Vec& v){
    // 17AD50: VU matrix, reciprocal W, all lanes multiplied by Q, VFTOI4.
    auto point=transform(m,v);
    if(!std::isfinite(point[3]) || point[3]==0)throw std::runtime_error("17AD50 unsupported projective W");
    const float q=vu_div(1.f,point[3]);std::array<std::int32_t,4> result{};
    for(unsigned i=0;i<4;++i){
        const float scaled=vu_mul(point[i],q)*16.f;
        if(!std::isfinite(scaled) || double(scaled)<INT32_MIN || double(scaled)>INT32_MAX)
            throw std::runtime_error("17AD50 projected coordinate exceeds fixed4 range");
        result[i]=static_cast<std::int32_t>(scaled);
    }
    return result;
}
}
