"""Pin LGPL Android shared FFmpeg artifacts for the test player's decoder."""
from android_bootstrap import BASE, download, fetch_json
import concurrent.futures, hashlib, json, shutil, tarfile

def install(abi):
    release = fetch_json('https://api.github.com/repos/tqk2811/FFmpegBuild/releases/tags/Release-Android-2026-08-06')
    name = f'ffmpeg-n7.1.5-1-g7d0e84200-android-{abi}-lgpl-shared-full.tar.xz'
    asset = next(a for a in release['assets'] if a['name'] == name)
    digest = asset.get('digest', '')
    path = download(asset['browser_download_url'], name, digest.removeprefix('sha256:') if digest else None)
    dest = BASE / 'ffmpeg' / abi
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, 'r:xz') as tar:
        members=tar.getmembers()
        for member in members:
            if not member.isfile():continue
            parts=member.name.split('/')
            # Keep archive layout, but do not install an executable or follow links.
            out=dest.joinpath(*parts)
            if not out.resolve().is_relative_to(dest.resolve()):raise RuntimeError('Unsafe archive path')
            out.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as src,out.open('wb') as target:shutil.copyfileobj(src,target)
    receipt={'abi':abi,'release':release['html_url'],'asset':name,'sha256':hashlib.file_digest(path.open('rb'),'sha256').hexdigest(),'upstream_digest':digest}
    (dest/'provenance.json').write_text(json.dumps(receipt,indent=2),encoding='utf-8')
    print(json.dumps(receipt),flush=True)

if __name__=='__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:list(pool.map(install,['arm64-v8a','x86_64']))
