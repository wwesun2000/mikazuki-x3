"""Compile the Java touch shell, assemble and sign a local test APK."""
from pathlib import Path
import argparse, hashlib, json, os, shutil, subprocess, zipfile
from xml.etree import ElementTree
from build_android import ROOT,DEPEND,TC,OUT,digest

APP=ROOT/'port/platform/android/app'
def main(abi):
    version=ElementTree.parse(APP/'AndroidManifest.xml').getroot().get('{http://schemas.android.com/apk/res/android}versionName')
    if not version or any(c not in '0123456789abcdefghijklmnopqrstuvwxyz.-' for c in version):raise ValueError('Invalid APK version')
    work=OUT/('apk-'+abi);work.mkdir(parents=True,exist_ok=True)
    sdk=Path(TC['sdk']);bt=sdk/'build-tools/35.0.0';java=Path(TC['java'])/'bin'
    android=sdk/'platforms/android-35/android.jar'
    def run(args):subprocess.run(list(map(str,args)),check=True)
    resources=work/'resources.zip'
    run([bt/'aapt2.exe','compile','--dir',APP/'res','-o',resources])
    unsigned=work/'unsigned.apk';generated=work/'generated';generated.mkdir(exist_ok=True)
    run([bt/'aapt2.exe','link','-I',android,'--manifest',APP/'AndroidManifest.xml','--java',generated,'-o',unsigned,resources])
    classes=work/'classes';classes.mkdir(exist_ok=True)
    sources=list((APP/'src').rglob('*.java'))+list(generated.rglob('*.java'))
    # Android's API stubs deliberately omit LambdaMetafactory. Compile against
    # the JDK 8 language runtime; D8 desugars lambdas for the declared min API.
    run([java/'javac.exe','-encoding','UTF-8','--release','8','-classpath',android,'-d',classes,*sources])
    jar=work/'classes.jar'
    with zipfile.ZipFile(jar,'w') as z:
        for p in classes.rglob('*.class'):z.write(p,p.relative_to(classes).as_posix())
    dex=work/'dex';dex.mkdir(exist_ok=True)
    run([java/'java.exe','-cp',bt/'lib/d8.jar','com.android.tools.r8.D8','--min-api','26','--lib',android,'--output',dex,jar])
    media=DEPEND/'ffmpeg'/abi
    with zipfile.ZipFile(unsigned,'a',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        z.write(dex/'classes.dex','classes.dex')
        libs=['libavutil.so','libswresample.so','libavcodec.so','libavformat.so','libswscale.so','libc++_shared.so']
        for name in libs:z.write(media/'lib'/name,'lib/'+abi+'/'+name)
        z.write(OUT/abi/'libmikazuki.so','lib/'+abi+'/libmikazuki.so')
        z.write(media/'LICENSE.txt','assets/FFmpeg-LGPL.txt')
        if (APP/'assets').exists():
            for p in (APP/'assets').rglob('*'):
                if p.is_file():z.write(p,'assets/'+p.relative_to(APP/'assets').as_posix())
    aligned=work/'aligned.apk';run([bt/'zipalign.exe','-P','16','-f','4',unsigned,aligned])
    keystore=OUT/'test-signing.keystore'
    if not keystore.exists():run([java/'keytool.exe','-genkeypair','-keystore',keystore,'-storepass','android','-keypass','android','-alias','mikazuki-test','-keyalg','RSA','-keysize','3072','-validity','3650','-dname','CN=Mikazuki X3 Test,O=wwesun2000'])
    release=ROOT/'local/releases/android';release.mkdir(parents=True,exist_ok=True)
    apk=release/f'MikazukiX3-Android-{version}-{abi}.apk'
    run([java/'java.exe','-jar',bt/'lib/apksigner.jar','sign','--ks',keystore,'--ks-pass','pass:android','--key-pass','pass:android','--out',apk,aligned])
    run([java/'java.exe','-jar',bt/'lib/apksigner.jar','verify','--verbose',apk])
    run([bt/'zipalign.exe','-c','-P','16','4',apk])
    record={'apk':str(apk),'sha256':digest(apk),'bytes':apk.stat().st_size,'abi':abi,'min_api':26,'target_api':35,
        'native':json.loads((OUT/abi/'build.json').read_text()),'ui_sources':{str(p.relative_to(ROOT)):digest(p) for p in sources if p.is_relative_to(APP)},
        'app_inputs':{str(p.relative_to(ROOT)):digest(p) for p in APP.rglob('*') if p.is_file()},
        'packager_sha256':digest(Path(__file__))}
    (release/f'MikazukiX3-Android-{version}-{abi}.json').write_text(json.dumps(record,indent=2),encoding='utf-8')
    print('APK',apk,apk.stat().st_size,record['sha256'])
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--abi',choices=['arm64-v8a','x86_64'],default='arm64-v8a');a=p.parse_args();main(a.abi)
