"""Run the project-owned Ghidra R5900 import/export with bounded owned processes."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
GHIDRA = ROOT / 'local/dependencies/ghidra-ee/ghidra_12.1.4_PUBLIC'
JDK = Path(os.environ['JAVA_HOME'])
TARGET = ROOT / 'local/extracted/SLPM_664.52'
TARGET_SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'


def run() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--process', action='store_true', help='Reuse the existing analyzed project without auto-analysis')
    parser.add_argument('--save-analysis', action='store_true', help='Save reviewed function-seeding metadata to the project')
    parser.add_argument('--project-location', type=Path, default=ROOT / 'local/ghidra-projects')
    parser.add_argument('--project-name', default='kamaitachi-ee')
    parser.add_argument('--post-script')
    parser.add_argument('--script-args', nargs='*', default=[])
    parser.add_argument('--timeout', type=int, default=900)
    args = parser.parse_args()
    produces_manifest = (args.post_script in ('ExportKamaitachiEvidence.java', 'ValidateKamaitachiMmi.java')
                         or bool(args.post_script and args.post_script.startswith('EmulateKamaitachi')))
    if produces_manifest and args.script_args and (Path(args.script_args[0]) / 'manifest.json').exists():
        raise ValueError('Existing evidence manifest: choose a fresh result directory')
    writable_scripts = {'SeedKamaitachiVmFunctions.java', 'RepairKamaitachiSharedReturns.java'}
    if args.save_analysis and (not args.process or args.post_script not in writable_scripts):
        raise ValueError('Saving analysis is restricted to reviewed VM metadata scripts')
    project_dir = args.project_location.resolve()
    if not project_dir.is_relative_to(ROOT) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', args.project_name):
        raise ValueError('Ghidra projects must have a simple name and remain inside this workspace')
    digest = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    if digest != TARGET_SHA:
        raise ValueError('Original ELF identity changed; refusing to reuse the fixed analysis profile')
    profile = ROOT / 'local/ghidra-profile'
    output = ROOT / 'analysis/ghidra'
    for directory in (project_dir, output, *(profile / s for s in ('home', 'settings', 'cache', 'temp'))):
        directory.mkdir(parents=True, exist_ok=True)
    vmargs = []
    for line in (GHIDRA / 'support/launch.properties').read_text().splitlines():
        if line.startswith(('VMARGS=', 'VMARGS_WINDOWS=')):
            vmargs.append(line.split('=', 1)[1])
    vmargs += ['-Xmx2G', '-XX:ActiveProcessorCount=4', '-Djava.awt.headless=true',
               f'-Duser.home={profile / "home"}', f'-Dapplication.settingsdir={profile / "settings"}',
               f'-Dapplication.cachedir={profile / "cache"}', f'-Dapplication.tempdir={profile / "temp"}',
               f'-Djava.io.tmpdir={profile / "temp"}']
    command = [str(JDK / 'bin/java.exe'), *vmargs, '-cp', str(GHIDRA / 'Ghidra/Framework/Utility/lib/Utility.jar'),
               'ghidra.Ghidra', 'ghidra.app.util.headless.AnalyzeHeadless', str(project_dir), args.project_name]
    if args.process:
        command += ['-process', TARGET.name, '-noanalysis']
        if not args.save_analysis:
            command += ['-readOnly']
    else:
        if (project_dir / (args.project_name + '.gpr')).exists():
            raise ValueError('Analysis project already exists; use --process instead of overwriting it')
        command += ['-import', str(TARGET), '-processor', 'r5900:LE:32:default', '-cspec', 'default',
                    '-analysisTimeoutPerFile', '600', '-max-cpu', '4']
    command += ['-scriptPath', str(ROOT / 'tools/ghidra')]
    if args.post_script:
        command += ['-postScript', args.post_script, *args.script_args]
    stamp = time.strftime('%Y%m%d-%H%M%S')
    log_path = output / f'{stamp}-{"export" if args.process else "import"}.log'
    audit_path = log_path.with_suffix('.run.json')
    audit = dict(target=str(TARGET), target_sha256=digest, language='r5900:LE:32:default',
                 command=command, log=str(log_path), started_at=time.time(), completed=False)
    env = dict(os.environ, JAVA_HOME=str(JDK))
    # The selected Java command and explicit application paths avoid global launcher settings.
    with log_path.open('wb') as log:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        audit['pid'] = process.pid
        audit_path.write_text(json.dumps(audit, indent=2), encoding='utf-8')
        print(json.dumps(dict(pid=process.pid, log=str(log_path), audit=str(audit_path))), flush=True)
        try:
            code = process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            # Only the exact still-running process created above and its descendants are owned.
            subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'], capture_output=True, check=False)
            code = process.wait(timeout=30)
            audit['timed_out'] = True
        audit.update(exit_code=code, completed=True, ended_at=time.time(), process_exited=process.poll() is not None)
    audit['target_sha256_after'] = hashlib.sha256(TARGET.read_bytes()).hexdigest()
    audit['target_unchanged'] = audit['target_sha256_after'] == digest
    # Ghidra can return process exit 0 even when a post-script throws.
    # Keep the native exit separately and check the export's own completion record.
    expected_script_status = None
    if args.post_script in ('ExportKamaitachiEvidence.java','ExportScreenCallbacks.java'):
        expected_script_status = 'export_completed'
    elif args.post_script == 'ValidateKamaitachiMmi.java':
        expected_script_status = 'mmi_validation_completed'
    elif args.post_script and args.post_script.startswith('EmulateKamaitachi'):
        expected_script_status = 'oracle_completed'
    if expected_script_status and args.script_args:
        manifest_path = Path(args.script_args[0]) / 'manifest.json'
        try:
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            audit['export_status'] = manifest.get('status')
            audit['export_fresh'] = manifest_path.stat().st_mtime >= audit['started_at']
            audit['export_verified'] = manifest.get('status') == expected_script_status and audit['export_fresh']
        except (OSError, ValueError) as error:
            audit['export_verified'] = False
            audit['export_error'] = str(error)
        if not audit['export_verified'] and code == 0:
            code = 2
    if not audit['target_unchanged'] and code == 0:
        code = 3
    audit['validated_exit_code'] = code
    audit_path.write_text(json.dumps(audit, indent=2), encoding='utf-8')
    print(json.dumps(dict(exit_code=code, elapsed_seconds=round(audit['ended_at']-audit['started_at'], 2),
                          log=str(log_path), target_unchanged=audit['target_unchanged'])), flush=True)
    return code if not audit.get('timed_out') else 124


if __name__ == '__main__':
    raise SystemExit(run())
