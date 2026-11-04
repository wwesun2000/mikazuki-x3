"""Replay the island's first hero selector and retain only input/return receipts."""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
def main():
    build=json.loads((ROOT/'local/pc-core/cold-story/build.json').read_bytes())
    runner=Path(build['output']);sha=hashlib.sha256(runner.read_bytes()).hexdigest()
    if sha!=build['output_sha256'].lower():raise ValueError('Frozen runner hash mismatch')
    response=subprocess.run([runner,ROOT,'sn4g','--actor-test','-'],capture_output=True,text=True,timeout=500)
    if response.returncode:raise ValueError((response.stdout,response.stderr))
    events=[json.loads(line) for line in response.stdout.splitlines()]
    if (events[0]['stage']!='entered' or events[-1].get('continued_label')!='yx01_0000' or
        not any(e.get('matched_label')=='top00_1200' and e.get('selector')==17 for e in events) or
        not any(e.get('stage')=='locked' and e.get('chosen')==0xffffffff and e.get('accepting') for e in events)):
        raise ValueError(events)
    report=dict(timestamp=datetime.now(timezone.utc).isoformat(),entry='original disc files, fixed source clock seed 4357',
                exe_sha256=sha,snapshot=build['snapshot_id'],scope='Native source callbacks, keyboard/mouse, four card slots, original labels and continuation; no physical GPU assertions',
                old_save_migration='separate detached-memory probes: existing stack, absent earlier field, repeated repair preserving active contents',
                events=events)
    path=ROOT/'analysis/native-core/actor-choice-from-original-files.json'
    path.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(report=str(path),labels=[e for e in events if 'matched_label' in e or 'continued_label' in e])))

if __name__=='__main__':main()
