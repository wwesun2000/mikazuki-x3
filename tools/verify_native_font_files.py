"""Compare complete Windows font provider outputs to execution of original 16BD88."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))
def check(condition,message):
    if not condition:raise RuntimeError(message)

def main():
    build_file=ROOT/'local/pc-core/media_state_probe.build.json'
    build=load(build_file)
    exe=Path(build['output'])
    oracle_file=ROOT/'analysis/ghidra/oracle-cold-font-resource-v2/manifest.json'
    oracle=load(oracle_file)
    check(oracle['status']=='oracle_completed' and oracle['source_entry']=='0x0016bd88','Missing original oracle')
    check(sha(ROOT/'local/extracted/SLPM_664.52')==oracle['source_elf_sha256'],'ELF changed')
    check(sha(ROOT/'tools/ghidra/EmulateKamaitachiFontResource.java')==oracle['harness_sha256'],'Original harness changed')
    def stable():return sha(exe)==build['output_sha256'] and all(sha(p)==h for p,h in build['sources'].items())
    check(stable(),'Native binary/sources changed')
    check([r['program'] for r in oracle['programs']]==['sn2','sn4','sn4g'],'Unexpected source set')
    rows=[]
    with tempfile.TemporaryDirectory(dir=ROOT/'local/pc-core') as tmp:
        for original in oracle['programs']:
            name=original['program']
            source=ROOT/'local/assets/SCENARIO'/f'{name}.fnt'
            check(sha(source)==original['source_sha256'],f'{name} file changed')
            dest=Path(tmp)/f'{name}.bin'
            child=subprocess.run([str(exe),str(ROOT),'--font-image',name,str(dest)],stdin=subprocess.DEVNULL,
                capture_output=True,text=True,timeout=30,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            check(child.returncode==0,child.stderr)
            native=json.loads(child.stdout)
            check(native['descriptor']==oracle['descriptor_address'] and dest.stat().st_size==original['resident_bytes'],
                  f'{name} source address/size mismatch')
            check(sha(dest)==original['resident_sha256'],f'{name} does not match original execution')
            rows.append({**original,'groups':native['groups'],'glyphs':native['glyphs'],'match':True})
    check(stable(),'Native build changed during verification')
    now=datetime.now(timezone.utc)
    result={'status':'passed','verified_utc':now.isoformat(),'oracle':str(oracle_file.relative_to(ROOT)),
        'oracle_sha256':sha(oracle_file),'native_build':str(build_file.relative_to(ROOT)),
        'native_build_sha256':sha(build_file),'native_probe_sha256':sha(exe),'programs':rows,
        'total_glyphs':sum(r['glyphs'] for r in rows),'compared_bytes':sum(r['resident_bytes'] for r in rows)}
    dest=ROOT/'analysis/native-core'/f'font-file-differential-{now:%Y%m%d-%H%M%S}.json'
    dest.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':'passed','fonts':len(rows),'bytes':result['compared_bytes'],'report':str(dest)}))
if __name__=='__main__':main()
