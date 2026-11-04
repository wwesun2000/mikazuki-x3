#pragma once
#include "ee_scalar.hpp"
namespace kx3::screen_mesh {
// Finite normal domain used by1904D0. Original1F9460 ultimately packs via
// 1FB500, discarding low significand bits rather than rounding to nearest.
// Retain the 106-bit product so host binary64 rounding cannot erase them.
inline double source_double_product(double a,double b){
 using u64=std::uint64_t;using u128=unsigned __int128;
 const auto x=std::bit_cast<u64>(a),y=std::bit_cast<u64>(b),sign=(x^y)&(u64(1)<<63);
 const auto ex=unsigned((x>>52)&2047),ey=unsigned((y>>52)&2047);
 if((!ex && (x&0x7fffffffffffffffull)) || (!ey && (y&0x7fffffffffffffffull)) || ex==2047 || ey==2047)
  throw std::runtime_error("1F9460 unsupported nonnormal double input");
 if(!ex || !ey)return std::bit_cast<double>(sign);
 const u128 product=u128((x&0xfffffffffffffull)|(u64(1)<<52))*u128((y&0xfffffffffffffull)|(u64(1)<<52));
 const unsigned upper=unsigned(product>>105);const int exponent=int(ex)+int(ey)-1023+int(upper);
 if(exponent<=0 || exponent>=2047)throw std::runtime_error("1F9460 unsupported double exponent result");
 const u64 significand=u64(product>>(52+upper));
 return std::bit_cast<double>(sign|(u64(exponent)<<52)|(significand&0xfffffffffffffull));
}
inline float source_double_to_float(double x){
 if(!std::isfinite(x) || (x!=0 && (std::abs(x)<std::numeric_limits<float>::min() || std::abs(x)>std::numeric_limits<float>::max())))
  throw std::runtime_error("1F99D0 unsupported finite float domain");
 return ee::round_towards_zero(x);
}
}
