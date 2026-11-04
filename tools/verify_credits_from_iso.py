"""Compare the original record offsets actually shown from each ending label to the ISO-bound credit catalog."""
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
labels={"sn2":"mmb14_3470","sn4":"my32_0120","sn4g":"ep05_0090"}
def main():
    build=json.loads((ROOT/"local/pc-core/cold-story/build.json").read_bytes())
    exe=Path(build["output"])
    if hashlib.sha256(exe.read_bytes()).hexdigest()!=build["output_sha256"].lower():raise ValueError("Wrong native probe")
    book=json.loads((ROOT/"localization/system/staff-roll.zh-Hans.json").read_bytes())
    def check(member):
        work=Path(member["path"]).stem.split("_")[0]
        proc=subprocess.run([exe,ROOT,work,"--credits-to-end","18000"],capture_output=True,text=True,timeout=180,check=True)
        result=json.loads(proc.stdout.strip())
        expected=sorted(r["offset"] for r in member["records"])
        if expected!=result["source_offsets"] or not result["end_command"]:raise ValueError(f"Incomplete ending {work}")
        return dict(program=work,origin=labels[work],started_from="original label in fresh ISO session",
                    staff_sha256=member["sha256"],**result)
    with ThreadPoolExecutor(max_workers=3) as pool:cases=list(pool.map(check,book["members"]))
    report=dict(probe_sha256=build["output_sha256"],cases=cases,
                scope="Original ending-label entries; not a cold playthrough from a title or a complete GS pixel comparison.")
    (ROOT/"analysis/native-core/credits-ending-paths.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print([(c["program"],c["distinct_lines"],c["end_command"]) for c in cases])

if __name__=="__main__":main()
