"""Capture the running local QA emulator through the app's own screenshot path."""
from pathlib import Path
import argparse, hashlib, json, subprocess, time

ROOT=Path(__file__).resolve().parents[1]
ADB=ROOT/'local/dependencies/android/sdk/platform-tools/adb.exe'
PACKAGE='org.wwesun2000.mikazukix3'

def main(label,serial,tap):
    if not serial.startswith('emulator-'):raise ValueError('This helper is restricted to a local QA emulator')
    if not label or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in label):raise ValueError('Use a simple evidence label')
    prefix=[str(ADB),'-s',serial]
    def call(*args):return subprocess.check_output(prefix+list(args))
    def stamp():
        r=subprocess.run(prefix+['shell','run-as',PACKAGE,'stat','-c','%Y','files/diagnostics/latest-capture.json'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return int(r.stdout) if r.returncode==0 else -1
    old=stamp()
    previous=subprocess.run(prefix+['shell','ls','/sdcard/Pictures/MikazukiX3'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    old_names=set(previous.stdout.decode().splitlines())
    # Avoid same-second filesystem mtime ambiguity without generating extra input.
    while time.time()<old+1.05:time.sleep(.05)
    call('shell','input','tap',str(tap[0]),str(tap[1])) # Actual visible Capture touch control.
    end=time.monotonic()+12
    while stamp()<=old:
        if time.monotonic()>end:raise RuntimeError('The Activity did not publish a new screenshot diagnostic')
        time.sleep(.2)
    state=call('shell','run-as',PACKAGE,'cat','files/diagnostics/latest-capture.json')
    parsed=json.loads(state)
    while True:
        names=call('shell','ls','-t','/sdcard/Pictures/MikazukiX3').decode().splitlines()
        name=next((n.strip() for n in names if n not in old_names and n.startswith(parsed['location']+'-') and n.endswith('.png')),None)
        if name:break
        if time.monotonic()>end:raise RuntimeError('Screenshot PNG was not published')
        time.sleep(.2)
    output=ROOT/'analysis/android';output.mkdir(parents=True,exist_ok=True)
    (output/(label+'.json')).write_bytes(state)
    # This is the PNG captured by the app, without the subsequent Android toast.
    png=call('exec-out','cat','/sdcard/Pictures/MikazukiX3/'+name)
    if not png.startswith(b'\x89PNG\r\n\x1a\n'):raise RuntimeError('Invalid captured PNG')
    (output/(label+'.png')).write_bytes(png)
    installed=call('shell','pm','path',PACKAGE).decode().strip().splitlines()[0].removeprefix('package:')
    installed_hash=call('shell','sha256sum',installed).decode().split()[0]
    metadata={'serial':serial,'captured_file':name,'installed_apk_sha256':installed_hash,
              'png_sha256':hashlib.sha256(png).hexdigest(),'state_sha256':hashlib.sha256(state).hexdigest(),
              'program':parsed.get('program'),'location':parsed['location'],'tick':parsed.get('tick'),'error':parsed.get('error')}
    (output/(label+'-receipt.json')).write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    print(json.dumps(metadata))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('label');p.add_argument('--serial',default='emulator-5554');p.add_argument('--tap',type=int,nargs=2,required=True,metavar=('X','Y'));a=p.parse_args();main(a.label,a.serial,a.tap)
