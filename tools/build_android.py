"""Reproducible Android native build; Windows player remains its own target."""
from pathlib import Path
import argparse, concurrent.futures, hashlib, json, os, shutil, subprocess, time

ROOT=Path(__file__).resolve().parents[1]
DEPEND=ROOT/'local/dependencies/android'
TC=json.loads((DEPEND/'toolchain.json').read_text())
BIN=Path(TC['ndk'])/'toolchains/llvm/prebuilt/windows-x86_64/bin'
OUT=ROOT/'local/android-build'
SOURCES=list(sorted((ROOT/'port/core').glob('*.cpp')))
SOURCES += [ROOT/'port/platform'/p for p in ['text_layer.cpp','story_localization.cpp','windows/project_game.cpp',
    'windows/project_checkpoint.cpp','windows/project_media.cpp','windows/project_movie.cpp','windows/project_font.cpp','windows/project_audio.cpp']]
SOURCES += list(sorted((ROOT/'port/platform/android').glob('*.cpp')))

def digest(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def build(abi,jobs):
    target={'arm64-v8a':'aarch64-linux-android26','x86_64':'x86_64-linux-android26'}[abi]
    work=OUT/abi;work.mkdir(parents=True,exist_ok=True)
    media=DEPEND/'ffmpeg'/abi
    generated=ROOT/'local/pc-core/player'
    flags=['--target='+target,'-std=c++20','-O2','-fPIC','-fno-fast-math','-ffp-contract=off','-fexceptions','-frtti',
           '-D_FILE_OFFSET_BITS=64','-I'+str(media/'include'),'-I'+str(generated)]
    inputs={str(p.relative_to(ROOT)):digest(p) for p in SOURCES}
    for folder in ['port/core','port/platform','port/platform/windows','port/platform/android']:
        inputs.update({str(p.relative_to(ROOT)):digest(p) for p in (ROOT/folder).glob('*.hpp')})
    for p in generated.glob('*locale_data.inc'):inputs[str(p.relative_to(ROOT))]=digest(p)
    fingerprint=hashlib.sha256(json.dumps(inputs,sort_keys=True).encode()).hexdigest()
    oldpath=work/'build-inputs.json';old=json.loads(oldpath.read_text()) if oldpath.exists() else {}
    previous=work/'build.json'
    previous_build=json.loads(previous.read_text()) if previous.exists() else {}
    headers={k:v for k,v in inputs.items() if not k.endswith('.cpp')}
    headers_changed=(headers!={k:v for k,v in old.items() if not k.endswith('.cpp')} or previous_build.get('flags')!=flags)
    def compile(p):
        name=str(p.relative_to(ROOT)).replace('\\','_').replace('/','_')+'.o';obj=work/name
        if obj.exists() and not headers_changed and old.get(str(p.relative_to(ROOT)))==inputs[str(p.relative_to(ROOT))]:return obj
        log=work/(name+'.log')
        with log.open('w') as f:r=subprocess.run([str(BIN/'clang++.exe'),*flags,'-c',str(p),'-o',str(obj)],stdout=f,stderr=subprocess.STDOUT)
        if r.returncode:raise RuntimeError(str(p)+'\n'+log.read_text(encoding='utf-8',errors='replace')[-10000:])
        print('compiled',abi,p.name,flush=True);return obj
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:objects=list(pool.map(compile,SOURCES))
    oldpath.write_text(json.dumps(inputs,indent=2),encoding='utf-8')
    exe=work/'libmikazuki.so'
    if not any(p.name=='native_bridge.cpp' for p in SOURCES):print('Objects ready; awaiting bridge');return
    rsp=work/'link.rsp'
    params=['--target='+target,'-shared','-Wl,-z,max-page-size=16384','-Wl,--no-undefined','-Wl,-soname,libmikazuki.so',
            *map(str,objects),'-L'+str(media/'lib'),'-lavformat','-lavcodec','-lavutil','-lswscale','-lswresample',
            '-landroid','-ljnigraphics','-laaudio','-llog','-o',str(exe)]
    rsp.write_text('\n'.join('"'+v.replace('\\','/')+'"' for v in params),encoding='utf-8')
    with (work/'link.log').open('w') as log:r=subprocess.run([str(BIN/'clang++.exe'),'@'+str(rsp)],stdout=log,stderr=subprocess.STDOUT)
    if r.returncode:raise RuntimeError((work/'link.log').read_text()[-12000:])
    subprocess.run([str(BIN/'llvm-strip.exe'),'--strip-debug',str(exe)],check=True)
    changed=[k for k,v in inputs.items() if digest(ROOT/k)!=v]
    if changed:raise RuntimeError('Sources changed during build: '+str(changed))
    (work/'build.json').write_text(json.dumps({'abi':abi,'target':target,'source_fingerprint':fingerprint,'inputs':inputs,
        'flags':flags,'output':str(exe),'sha256':digest(exe)},indent=2),encoding='utf-8')
    print('linked',abi,exe.stat().st_size,digest(exe),flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--abi',choices=['arm64-v8a','x86_64'],default='arm64-v8a');p.add_argument('--jobs',type=int,default=4)
    a=p.parse_args();build(a.abi,a.jobs)
