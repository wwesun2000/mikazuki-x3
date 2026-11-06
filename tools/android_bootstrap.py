"""Download a project-local Android toolchain; never alter the global SDK/JDK."""
from pathlib import Path
import concurrent.futures, hashlib, json, shutil, urllib.request, zipfile

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "local/dependencies/android"
BASE.mkdir(parents=True, exist_ok=True)

def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "MikazukiX3-Android-build"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.load(r)

def download(url, name, digest=None, algorithm="sha256"):
    target = BASE / name
    if target.exists() and (not digest or hashlib.file_digest(target.open("rb"), algorithm).hexdigest() == digest):
        return target
    print("download", name, flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "MikazukiX3-Android-build"})
    part = target.with_suffix(target.suffix + ".part")
    with urllib.request.urlopen(req, timeout=120) as src, part.open("wb") as dst:
        shutil.copyfileobj(src, dst, 1024 * 1024)
    actual = hashlib.file_digest(part.open("rb"), algorithm).hexdigest()
    if digest and actual != digest:
        raise RuntimeError(f"Hash mismatch: {name}: {actual}")
    part.replace(target)
    print("downloaded", name, target.stat().st_size, actual, flush=True)
    return target

def sdk():
    path = download("https://dl.google.com/android/repository/commandlinetools-win-15859902_latest.zip", "cmdline-tools.zip",
                    "90ae805d20434428bffcb699c290860f19bb5f66a67e6b330067e3de801fb04a")
    dest = BASE / "sdk/cmdline-tools/latest"
    if not (dest / "bin/sdkmanager.bat").exists():
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                rel = Path(info.filename).relative_to("cmdline-tools")
                out = dest / rel
                if info.is_dir():out.mkdir(parents=True, exist_ok=True)
                else:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(info) as src, out.open("wb") as dst:shutil.copyfileobj(src, dst)
    return {"sdk": str(BASE / "sdk")}

def ndk():
    path = download("https://dl.google.com/android/repository/android-ndk-r28c-windows.zip", "ndk-r28c.zip",
                    "086bba43ff2f5eb0e387b15c8278bb4e0d89ba1d", "sha1")
    if not (BASE / "android-ndk-r28c/toolchains/llvm/prebuilt/windows-x86_64/bin/clang++.exe").exists():
        with zipfile.ZipFile(path) as z:z.extractall(BASE)
    return {"ndk": str(BASE / "android-ndk-r28c")}

def java():
    assets = fetch_json("https://api.adoptium.net/v3/assets/latest/21/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse")
    item = assets[0];p = item["binary"]["package"]
    path = download(p["link"], p["name"], p["checksum"])
    with zipfile.ZipFile(path) as z:
        dirname = z.namelist()[0].split("/")[0]
        if not (BASE / dirname / "bin/javac.exe").exists():z.extractall(BASE)
    return {"java": str(BASE / dirname), "java_version": item["version"]["semver"]}

if __name__ == "__main__":
    result = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for data in pool.map(lambda f:f(), [sdk, ndk, java]):result.update(data)
    (BASE / "toolchain.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result), flush=True)
    # Install the minimal SDK packages used by package_android.py. Keep Java
    # and SDK settings scoped to this child process, not the user's environment.
    import os, subprocess
    sdk_root=Path(result['sdk'])
    required=[sdk_root/'platforms/android-35/android.jar',sdk_root/'build-tools/35.0.0/aapt2.exe',sdk_root/'platform-tools/adb.exe']
    if not all(p.is_file() for p in required):
        env=os.environ.copy();env['JAVA_HOME']=result['java'];env['ANDROID_SDK_ROOT']=str(sdk_root)
        subprocess.run([str(sdk_root/'cmdline-tools/latest/bin/sdkmanager.bat'),'--sdk_root='+str(sdk_root),
                        'platform-tools','platforms;android-35','build-tools;35.0.0'],
                       env=env,input='y\n'*20,text=True,check=True)
        if not all(p.is_file() for p in required):raise RuntimeError('Android SDK installation is incomplete')
