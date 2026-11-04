"""Record actual cold controls and the next reached source boundary in each game."""
import concurrent.futures
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--deep',action='store_true',help='Also walk repeatable multi-choice routes from the original files')
    deep=parser.parse_args().deep
    build=json.loads((ROOT/'local/pc-core/cold-story/build.json').read_bytes())
    exe=Path(build['snapshot'])/'cold_story_probe.exe'
    fingerprint=hashlib.sha256(exe.read_bytes()).hexdigest()
    if fingerprint!=build['output_sha256'].lower():
        raise ValueError('Snapshot executable identity mismatch')

    def run(job):
        game,mode,budget,*arguments=job
        result=subprocess.run([exe,ROOT,game,mode,str(budget),*arguments],capture_output=True,text=True,timeout=500)
        rows=[json.loads(line) for line in result.stdout.splitlines()]
        if mode=='--wait-test':
            if result.returncode or [r['stage'] for r in rows]!=['entered','held','confirmed']:
                raise ValueError((game,result.stderr))
            if rows[0]['cursor']!=rows[1]['cursor'] or rows[1]['context_vtable']==rows[2]['context_vtable']:
                raise ValueError((game,'Wait protocol mismatch'))
        elif mode=='--device':
            if result.returncode or rows[-1]['played_stereo_frames']<1600 or rows[-1]['source_pcm_peak']<=0:
                raise ValueError((game,result.stderr))
        elif mode=='--walk' and ('mouse' in arguments or 'keyboard' in arguments):
            branch=rows[-1] if rows else {}
            expected=('mm01_0025','mmb01_0010')[int(arguments[-1])]
            if result.returncode or branch.get('stage')!='branch' or branch.get('label')!=expected:
                raise ValueError((game,arguments,result.stderr,branch))
        else:
            if not rows or rows[-1]['accepted_waits']<{'sn2':2,'sn4':1,'sn4g':5}[game]:
                raise ValueError((game,result.stderr,rows[-1:]))
            if result.returncode and (rows[-1]['stage']!='stopped' or not result.stderr.strip()):
                raise ValueError((game,'Missing source frontier'))
        return dict(game=game,mode=mode,arguments=arguments,frames_limit=budget,returncode=result.returncode,
                    frontier=result.stderr.strip(),observed=rows)

    jobs=[(game,'--wait-test',1500) for game in ('sn2','sn4','sn4g')]
    jobs += [(game,'--walk',10000,'--accept-default-names') for game in ('sn2','sn4')]
    jobs += [('sn4g','--walk',64000)]
    jobs += [('sn2','--walk',4000,'--accept-default-names',device,str(option))
             for device in ('mouse','keyboard') for option in (0,1)]
    jobs += [('sn4g','--device',420)]
    if deep:
        jobs += [('sn2','--route',60000,'--accept-default-names','keyboard',*['0']*16),
                 ('sn2','--route',60000,'--accept-default-names','mouse','1','1',*['0']*14),
                 ('sn4','--route',60000,'--accept-default-names','keyboard',*['0']*16)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        cases=list(pool.map(run,jobs))
    now=datetime.now(timezone.utc)
    report=ROOT/'analysis/native-core'/f'cold-controls-{now:%Y%m%d-%H%M%S}.json'
    report.write_text(json.dumps(dict(utc=now.isoformat(),exe_sha256=fingerprint,snapshot=build['snapshot_id'],
                                      cases=cases),indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(report=str(report),routes=[(r['game'],r['observed'][-1]['tick'],r['frontier'])
                                                     for r in cases if r['mode'] in ('--walk','--route')])))


if __name__=='__main__':
    main()
