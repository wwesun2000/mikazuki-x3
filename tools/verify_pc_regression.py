"""Run the fixed, independent original-instruction comparison suites for one build."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

ROOT=Path(__file__).resolve().parents[1]
ANALYSIS=ROOT/'analysis/native-core'
GROUPS={
    'diff_pc_core.py': {'readers-v1':470,'strings-v1':56,'history-v1':809,'tables-v1':460,
        'libc-v1':292,'choice-v1':154,'dispatch-v1':355,'manager-v1':300,'media-v1':264,'mmi-libc-v3':248},
    'diff_original_state_calls.py': {'control-transfer-v1':54,'choice-transfer-enhanced-v1':33,
        'text-base-v3':71,'text-ready-v1':4,'text-glyph-v1':4,'text-ruby-v1':4,'text-styles-v1':9,
        'text-timer-v1':27,'text-gate-v1':7,'manager-input-slot4-v1':5,'manager-input-slot7-v1':7,'page-control-v1':21},
}
def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def main():
    build_file=ROOT/'local/pc-core/core_probe.build.json'
    build=json.loads(build_file.read_text(encoding='utf-8-sig'))
    build_hash=digest(build_file)
    completed={}
    built_at=datetime.fromisoformat(build['built_utc']).timestamp()
    for pattern in ['diff-*.json','state-calls-*.json']:
        for path in ANALYSIS.glob(pattern):
            if path.stat().st_mtime+1<built_at:continue
            record=json.loads(path.read_text(encoding='utf-8-sig'))
            if record.get('probe_build_manifest',record.get('build'))!=build or not record.get('all_passed'):continue
            directory=Path(record.get('oracle_directory',record.get('oracle','')))
            if 'oracle_cases_sha256' in record:
                valid=(record.get('build_stable_during_run') and digest(directory/'cases.jsonl')==record['oracle_cases_sha256']
                       and digest(directory/'manifest.json')==record['oracle_manifest_sha256'])
            else:
                manifest=record['oracle_manifest']
                valid=(manifest==json.loads((directory/'manifest.json').read_text()) and digest(directory/'cases.jsonl')==manifest['cases_sha256']
                       and digest(directory/'input-plan.json')==manifest['source_plan_sha256'])
            if valid:completed[directory.name]=path
    def run(group):
        runner,name,n=group
        path=completed.get('oracle-'+name)
        if path is None:
            child=subprocess.run([sys.executable,str(ROOT/'tools'/runner),str(ROOT/'analysis/ghidra'/('oracle-'+name))],
                cwd=ROOT,capture_output=True,encoding='utf-8',errors='replace',timeout=360)
            if child.returncode:raise RuntimeError(f'{name}: {child.stdout[-1200:]} {child.stderr[-1200:]}')
            last=child.stdout.strip().splitlines()[-1]
            path=Path(last if runner=='diff_pc_core.py' else json.loads(last)['report'])
        report=json.loads(path.read_text(encoding='utf-8-sig'))
        if not report['all_passed'] or report['cases']!=n or report['passed']!=n:
            raise ValueError(f'{name}: mismatched cases')
        if report.get('probe_build_manifest',report.get('build'))!=build:
            raise ValueError(f'{name}: different core build')
        return {'group':name,'cases':n,'report':str(path.relative_to(ROOT)),'report_sha256':digest(path)}
    groups=[(runner,name,n) for runner,items in GROUPS.items() for name,n in items.items()]
    with ThreadPoolExecutor(max_workers=4) as workers:rows=list(workers.map(run,groups))
    if digest(build_file)!=build_hash or any(digest(p)!=h for p,h in build['sources'].items()):
        raise RuntimeError('Core changed during regression run')
    now=datetime.now(timezone.utc)
    report={'status':'passed','kind':'central native probes versus original ELF instruction oracles',
        'utc':now.isoformat(),'core_build_sha256':build_hash,'core_probe_sha256':build['output_sha256'],
        'state_call_probe_sha256':build['state_call_sha256'],'cases':sum(r['cases'] for r in rows),'groups':rows,
        'scope':'Function and persistent-state samples. Readback uses its own separate 14-case probe.'}
    target=ANALYSIS/f'central-regression-{now:%Y%m%d-%H%M%S}.json'
    target.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':'passed','cases':report['cases'],'groups':len(rows),'report':str(target)}))
if __name__=='__main__':main()
