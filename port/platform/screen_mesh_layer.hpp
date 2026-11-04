#pragma once
#include "../core/screen_mesh.hpp"
#include "raster_frame.hpp"
#include <algorithm>
namespace kx3::platform {
// Source1912D8 submits packed UV/RGBAQ/XYZF2, PRIM153. The saved display
// texture is nearest/clamped; no perspective STQ correction is involved.
inline void draw_screen_mesh_layer(RasterFrame& frame,const GuestMemory& memory,
                                     std::span<const screen_mesh::Triangle> triangles){
 if(frame.width!=640 || frame.height!=448 || frame.rgba.size()!=640*448*4)
  throw std::runtime_error("Original crash-wipe requires 640x448 display fields");
 struct Point{std::int64_t x,y,u,v;};
 const auto cross=[](const Point& a,const Point& b,const Point& p){return (b.x-a.x)*(p.y-a.y)-(b.y-a.y)*(p.x-a.x);};
 const auto inclusive=[](const Point& a,const Point& b){return b.y<a.y || (b.y==a.y && b.x>a.x);};
 for(unsigned field=0;field<2;++field){
  const auto plane=memory.read_u32(0x236114+4*field);
  if(!plane)throw std::runtime_error("191168 requires captured display fields");
  const auto source=memory.bytes(plane,640*224*4);
  for(const auto& triangle:triangles){
   if(triangle.alpha>128)throw std::runtime_error("Invalid original crash-wipe alpha");
   if(!triangle.alpha)continue;
   std::array<Point,3> p{};
   for(unsigned i=0;i<3;++i){const auto& v=triangle.vertices[i];
    p[i]={std::int64_t(std::uint32_t(v.x)&0xffff)-1728*16,std::int64_t(std::uint32_t(v.y)&0xffff)-1936*16-8*field,
          std::uint32_t(v.u)&0x3fff,std::uint32_t(v.v)&0x3fff};}
   auto area=cross(p[0],p[1],p[2]);if(!area)continue;
   if(area<0){std::swap(p[1],p[2]);area=-area;}
   const int left=int(std::clamp<std::int64_t>((std::min({p[0].x,p[1].x,p[2].x})+15)/16,0,640));
   const int right=int(std::clamp<std::int64_t>((std::max({p[0].x,p[1].x,p[2].x})+15)/16,0,640));
   const int top=int(std::clamp<std::int64_t>((std::min({p[0].y,p[1].y,p[2].y})+15)/16,0,224));
   const int bottom=int(std::clamp<std::int64_t>((std::max({p[0].y,p[1].y,p[2].y})+15)/16,0,224));
   for(int y=top;y<bottom;++y)for(int x=left;x<right;++x){
    const Point sample{16*x,16*y,0,0};
    const auto wa=cross(p[1],p[2],sample),wb=cross(p[2],p[0],sample),wc=cross(p[0],p[1],sample);
    if(wa<0 || wb<0 || wc<0 || (!wa&&!inclusive(p[1],p[2])) || (!wb&&!inclusive(p[2],p[0])) || (!wc&&!inclusive(p[0],p[1])))continue;
    const auto u=std::clamp<std::int64_t>((wa*p[0].u+wb*p[1].u+wc*p[2].u)/(16*area),0,639);
    const auto v=std::clamp<std::int64_t>((wa*p[0].v+wb*p[1].v+wc*p[2].v)/(16*area),0,223);
    const auto* src=source.data()+4*(640*v+u);auto* dst=frame.rgba.data()+4*(640*(2*y+field)+x);
    for(unsigned c=0;c<3;++c)dst[c]=std::uint8_t(int(dst[c])+((int(src[c])-int(dst[c]))*int(triangle.alpha)>>7));
   }
  }
 }
}
}
