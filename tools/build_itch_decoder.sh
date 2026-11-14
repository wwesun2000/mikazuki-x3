#!/usr/bin/env bash
set -euo pipefail
# Ubuntu 24.04: gcc-mingw-w64-x86-64, make, nasm, curl, xz-utils, zip.
# No external codec libraries, network protocols, GPL or nonfree switches.
mkdir -p build/itch-decoder
cd build/itch-decoder
curl --fail --location --proto '=https' https://ffmpeg.org/releases/ffmpeg-7.1.tar.xz -o ffmpeg-7.1.tar.xz
echo '40973d44970dbc83ef302b0609f2e74982be2d85916dd2ee7472d30678a7abe6  ffmpeg-7.1.tar.xz' | sha256sum --check
tar -xf ffmpeg-7.1.tar.xz
cd ffmpeg-7.1
./configure --target-os=mingw32 --arch=x86_64 --enable-cross-compile \
  --cross-prefix=x86_64-w64-mingw32- --pkg-config=false \
  --disable-autodetect --disable-network --disable-everything \
  --disable-doc --disable-debug --disable-ffplay --disable-ffprobe \
  --disable-shared --enable-static --enable-ffmpeg \
  --enable-protocol=file,pipe --enable-demuxer=ipu,ogg,mpegps,mpegvideo \
  --enable-decoder=ipu,vorbis,mpeg1video,mpeg2video \
  --enable-parser=mpegvideo,vorbis --enable-encoder=rawvideo,pcm_s16le \
  --enable-muxer=rawvideo,pcm_s16le \
  --enable-filter=scale,format,aresample,aformat,null,anull \
  --enable-swscale --enable-swresample --extra-ldflags=-static
make -j2 ffmpeg.exe
mkdir -p ../package/licenses
cp ffmpeg.exe ../package/ffmpeg.exe
cp COPYING.LGPLv2.1 ../package/licenses/FFmpeg-LICENSE.txt
cp ../ffmpeg-7.1.tar.xz ../package/licenses/ffmpeg-7.1.tar.xz
cp ffbuild/config.log ../package/licenses/FFmpeg-config.log
cp ../../../tools/build_itch_decoder.sh ../package/licenses/build_itch_decoder.sh
cp ../../../docs/itch/FFmpeg-SOURCE.txt ../package/licenses/FFmpeg-SOURCE.txt
cp ../../../docs/itch/THIRD-PARTY-NOTICES.txt ../package/licenses/THIRD-PARTY-NOTICES.txt
x86_64-w64-mingw32-objdump -p ffmpeg.exe | grep 'DLL Name' > ../package/licenses/FFmpeg-imports.txt
cd ../package
sha256sum ffmpeg.exe licenses/* > SHA256SUMS.txt
zip -r ../MikazukiX3-decoder-source.zip .
