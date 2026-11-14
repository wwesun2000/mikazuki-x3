"""Stage an exact reviewed GitHub Release asset, never private compile inputs."""
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.request
import urllib.error
import urllib.parse
import zipfile
from package_itch import DECODER, DECODER_SHA256, LEGAL_TEXTS, SOURCE_SHA256, pe64

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None

def stage(archive, expected, dest):
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('Expected a reviewed SHA256')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
        raise ValueError('Release ZIP hash mismatch')
    allowed = {'.itch.toml', 'MikazukiX3.exe', 'README.txt', 'SHA256SUMS.txt',
               'local/pc-core/player/KamaitachiX3.exe', DECODER,
               'licenses/ffmpeg-7.1.tar.xz'} | {'licenses/'+n for n in LEGAL_TEXTS}
    with zipfile.ZipFile(archive) as z:
        if len(z.namelist()) != len(allowed) or set(z.namelist()) != allowed:
            raise ValueError('Unreviewed or duplicate ZIP entry')
        if sum(x.file_size for x in z.infolist()) > 256*1024*1024:
            raise ValueError('Unexpected package size')
        files = {n:z.read(n) for n in allowed}
    for n in ('MikazukiX3.exe', 'local/pc-core/player/KamaitachiX3.exe', DECODER):
        pe64(files[n])
    for n,h in [(DECODER,DECODER_SHA256),('licenses/ffmpeg-7.1.tar.xz',SOURCE_SHA256)]:
        if hashlib.sha256(files[n]).hexdigest()!=h:
            raise ValueError('Reviewed decoder/source mismatch')
    expected_manifest=''.join(f'{hashlib.sha256(files[n]).hexdigest()}  {n}\n'
                              for n in sorted(allowed-{'SHA256SUMS.txt'})).encode()
    if files['SHA256SUMS.txt']!=expected_manifest:
        raise ValueError('Per-file manifest mismatch')
    dest.mkdir(parents=True,exist_ok=False)
    for n,data in files.items():
        p=dest/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    print(f'PASS: exact reviewed ZIP, {len(allowed)} allowlisted files, decoder/source identity, per-file hashes; no disc/BIOS/media/cache paths.')

def main():
    asset=os.environ['ITCH_ASSET_ID'];expected=os.environ['ITCH_ASSET_SHA256'].lower()
    if not asset.isdigit():raise SystemExit('Numeric GitHub asset ID required')
    req=urllib.request.Request('https://api.github.com/repos/wwesun2000/mikazuki-x3/releases/assets/'+asset,
        headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],'Accept':'application/octet-stream','X-GitHub-Api-Version':'2022-11-28'})
    opener=urllib.request.build_opener(NoRedirect)
    try:
        try:
            response=opener.open(req,timeout=60)
        except urllib.error.HTTPError as e:
            if e.code not in (301,302,303,307,308):raise
            url=e.headers['Location'];parsed=urllib.parse.urlparse(url)
            if parsed.scheme!='https' or not (parsed.hostname or '').endswith('.githubusercontent.com'):
                raise ValueError('Unexpected asset CDN')
            # Never forward the repository credential to the CDN.
            response=urllib.request.urlopen(url,timeout=60)
        path=Path('build/reviewed.zip');path.parent.mkdir(parents=True,exist_ok=True)
        with response,path.open('wb') as out:
            total=0
            while chunk:=response.read(1024*1024):
                total+=len(chunk)
                if total>128*1024*1024:raise ValueError('Oversized download')
                out.write(chunk)
    except urllib.error.HTTPError as e:
        raise SystemExit('Reviewed asset download HTTP status '+str(e.code)+' (response/URLs suppressed)') from None
    except Exception as e:
        print('Download failure category: '+type(e).__name__)
        raise SystemExit('Reviewed asset download failed (credential and signed URLs suppressed)') from None
    stage(path,expected,Path('build/MikazukiX3-Windows'))

if __name__=='__main__':main()
