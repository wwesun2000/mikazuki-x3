"""Register a selected cold-session Win32 screenshot using its actual run receipt."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import shutil
from pathlib import Path
from capture_catalog import PROJECT_ROOT,register

CASES={
    "gate_wait":("player-english-waits","capture","sn4g","12:B3465/B34A8","Original gate scene and the first Chinese clause, before the door and the person waving are revealed."),
    "brightness":("player-brightness","capture","sn4g","114BB0/135858","The cafe checkpoint in original R2 inspection mode with text hidden and brightness set to 50."),
    "interval":("player-interval","capture","sn4g","122328/223C70","Cold-start interval selector, showing level four after a mouse click."),
    "controls":("player-controls","capture","sn4g","141DA8/2072F8","Retail help labels from the cold-start café, displayed while the original R1 input is held."),
    "menu":("player-menu-window","menu_capture","sn4g","first eligible system menu","Original system menu in the café before Save and Quit."),
    "name":("player-name","name_capture","sn2","name slot 0","First protagonist name editor using the original character grid."),
    "charts":("player-charts","chart_capture","sn4g","system time chart","Accessible time-chart cells from the first original system menu."),
    "snow":("player-snow","snow_capture","sn4g","183258/1836D8","Cold story with on-screen snow sprites and the source narration bound on the same frame."),
    "ski-choice":("player-choice-a","choice_capture","sn2","ordinary choice 6C at file offset 0x50E2","First ski-slope choice in the cold story, after the two original name editors. Both original rows are ready."),
    "actors":("player-actors","actor_capture","sn4g","7F actor panel / 14B2A0","First cold-session character selection. The original artwork shows Seiichi Kayama and three locked portrait slots."),
}

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("case",choices=CASES)
    case=parser.parse_args().case
    name,key,program,source_id,caption=CASES[case]
    root=PROJECT_ROOT;receipt=root/"analysis/native-core"/(name+".json")
    data=receipt.read_bytes();result=json.loads(data)
    run=json.loads(receipt.with_name(name+"-run.json").read_text(encoding="utf-8"))
    path=root/result[key]
    verified=result["status"]=="verified" if case=="gate_wait" else result["status"].startswith("verified-")
    if(not verified or run["exit_code"] or not run["exited"]
       or hashlib.sha256(data).hexdigest()!=run["report_sha256"].lower()
       or hashlib.sha256(path.read_bytes()).hexdigest()!=run[key+"_sha256"].lower()):
        raise ValueError("Screenshot is not bound to a successful run receipt")
    archive=root/"captures/runtime/pc-player"/path.name
    if(path!=archive):
        if archive.exists():
            if hashlib.sha256(archive.read_bytes()).digest()!=hashlib.sha256(path.read_bytes()).digest():
                raise SystemExit("A representative capture already exists. Preserve the registered artwork and use the local QA frame for this rerun.")
        else:
            archive.parent.mkdir(parents=True,exist_ok=True)
            try:
                archive.hardlink_to(path)  # QA captures are replaced atomically on reruns.
            except OSError:
                with path.open("rb") as src,archive.open("xb") as dst:shutil.copyfileobj(src,dst)
        path=archive
    stamp=datetime.fromtimestamp(path.stat().st_mtime,timezone.utc).isoformat()
    evidence=register(root,path,kind="runtime-screenshot",status="captured",source_sha256="50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160",
        source_asset_id=f"SLPM_664.52+{program}/{source_id}",recorded_at=stamp,language="zh-Hans",
        stage="native-windows-player-resumed" if case=="brightness" else "native-windows-player-targeted-scene" if case=="gate_wait" else "native-windows-player-cold-start",
        spoiler="minor",description=caption,notes="Retail files, original progress and input conditions, Chinese draft UI.",
        render_settings=dict(backend="Win32 GDI",capture="WM_PRINTCLIENT/WIC PNG",client=[1120,700],scanlines=False,scale2x=False,
            smooth_scaling=True,exe_sha256=run["executable_sha256"].lower(),source_receipt=receipt.relative_to(root).as_posix()))
    print(evidence["result"],evidence["asset_id"])
