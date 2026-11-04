"""Compare each native WIC output pixel to a fresh FFmpeg decode of original FAD bytes."""
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'local/pc-core/movie-playback'


def sha(data):return hashlib.sha256(data).hexdigest()


def main():
    report_path=ROOT/'analysis/native-core/movie-catalog.json'
    catalog=json.loads(report_path.read_bytes())
    decode=json.loads((ROOT/'analysis/scenario_decode.json').read_bytes())
    ffmpeg=Path(decode['tool'])
    if sha(ffmpeg.read_bytes())!=catalog['ffmpeg_sha256']:raise RuntimeError('FFmpeg identity changed')
    toolchain=ROOT/'local/dependencies/ps2recomp/_evaluation'
    zig=toolchain/'toolchain/zig-x86_64-windows-0.15.2/zig.exe'
    sources=[ROOT/f for f in ('port/tests/movie_playback_probe.cpp','port/platform/windows/project_movie.cpp',
             'port/platform/windows/raster_loader.cpp','port/platform/windows/source_codec.cpp','port/core/pss_audio.cpp')]
    tracked=sources+[ROOT/f for f in ('port/platform/windows/project_movie.hpp','port/platform/windows/raster_loader.hpp',
            'port/platform/raster_frame.hpp','port/platform/movie_catalog.hpp','port/core/source_movie.hpp',
            'port/platform/movie_stream_index.hpp','port/platform/original_media_catalog.hpp','port/platform/windows/source_codec.hpp',
            'port/core/pss_audio.hpp','port/core/retail_disc.hpp')]
    identities={p.relative_to(ROOT).as_posix():sha(p.read_bytes()) for p in tracked}
    OUT.mkdir(parents=True,exist_ok=True)
    exe=OUT/'movie_playback_probe.exe'
    env={**os.environ,'ZIG_GLOBAL_CACHE_DIR':str(toolchain/'zig-global-cache'),'ZIG_LOCAL_CACHE_DIR':str(OUT/'zig-cache')}
    subprocess.run([str(zig),'c++','-std=c++20','-target','x86_64-windows-gnu','-O2',*map(str,sources),
                    '-lole32','-lwindowscodecs','-luuid','-lbcrypt','-o',str(exe)],env=env,check=True,timeout=180)
    native=subprocess.run([str(exe),str(ROOT)],capture_output=True,text=True,check=True,timeout=180)
    actual=[json.loads(line) for line in native.stdout.splitlines()]
    index=0; evidence=[]
    with TemporaryDirectory(dir=OUT) as directory:
        for src in catalog['assets']:
            raw=(ROOT/src['path']).read_bytes()
            if sha(raw)!=src['sha']:raise RuntimeError('Source movie changed')
            for member,c in enumerate(catalog['clips'][src['start']:src['start']+src['clips']]):
                data=raw[c['offset']:c['offset']+c['encoded_bytes']]
                if sha(data)!=c['source']:raise RuntimeError('Source member changed')
                file=Path(directory)/('original.pss' if src['path'].endswith('.pss') else 'original.m2v')
                file.write_bytes(data)
                run=subprocess.run([str(ffmpeg),'-nostdin','-hide_banner','-v','error','-xerror','-err_detect','explode',
                    '-i',str(file),'-map','0:v:0','-an','-fps_mode','passthrough','-pix_fmt','rgba','-f','framehash',
                    '-hash','sha256','pipe:1'],capture_output=True,text=True,check=True,timeout=120)
                expected=[s.split(',')[-1].strip() for s in run.stdout.splitlines() if s and not s.startswith('#')]
                if run.stderr or len(expected)!=c['frames']:raise RuntimeError('Independent MPEG decode failed')
                for frame,digest in enumerate(expected):
                    row=actual[index];index+=1
                    if row!={'movie':src['virtual'],'member':member,'frame':frame,'rgba_sha256':digest}:
                        raise RuntimeError(f'WIC/FFmpeg pixel disagreement in {src["virtual"]} {member}:{frame}')
                evidence.append(dict(movie=src['virtual'],member=member,frames=len(expected),
                    rgba_sequence_sha256=sha(b''.join(bytes.fromhex(x) for x in expected)),first=expected[0],last=expected[-1]))
    if index!=len(actual) or any(sha(p.read_bytes())!=identities[p.relative_to(ROOT).as_posix()] for p in tracked):
        raise RuntimeError('Native build or frame sequence changed')
    now=datetime.now(timezone.utc)
    record=dict(status='passed',scope='Original MPEG members through the native streaming reader vs an offline FFmpeg decode of the same bytes; 30 fps on native 60 Hz clock, MMV play-once and loop',
                verified_utc=now.isoformat(),catalog_sha256=sha(report_path.read_bytes()),ffmpeg_sha256=catalog['ffmpeg_sha256'],
                source_elf_sha256=catalog['source_elf_sha256'],native_sha256=sha(exe.read_bytes()),sources=identities,
                verified_frames=index,clips=evidence)
    path=ROOT/'analysis/native-core'/f'movie-playback-{now:%Y%m%d-%H%M%S}.json'
    with path.open('x',encoding='utf-8') as out:out.write(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status='passed',frames=index,report=str(path))))


if __name__=='__main__':main()
