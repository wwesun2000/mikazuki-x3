"""Compare all mixed movie PCM ticks with independently demuxed, PTS-aligned ADS audio."""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import subprocess

from verify_media_payloads import private_stream

ROOT=Path(__file__).resolve().parents[1]
def sha(data):return hashlib.sha256(data).hexdigest()


def main():
    d=ROOT/'analysis/native-core'
    sources=sorted(d.glob('pss-audio-field-capture-*.json'))[-1]
    evidence=json.loads(sources.read_bytes())
    clips=json.loads((d/'movie-stream-verified.json').read_bytes())
    records={row['name']:row for row in clips['assets']}
    inputs=[p for p in evidence['pss'] if p['audio']]
    ff=ROOT/'local/dependencies/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe'
    if sha(ff.read_bytes())!=evidence['ffmpeg_sha256']:raise ValueError('Unexpected FFmpeg version')
    build=json.loads((ROOT/'local/pc-core/cold-story/build.json').read_bytes())
    probe=Path(build['snapshot'])/'cold_story_probe.exe'
    names=['MOVIE/'+Path(p['source']).name for p in inputs]
    child=subprocess.run([probe,ROOT,'--movie-audio',*names],capture_output=True,text=True,timeout=240)
    if child.returncode:raise RuntimeError(child.stderr)
    output=[json.loads(s) for s in child.stdout.splitlines()]
    for row,name,native in zip(inputs,names,output,strict=True):
        data=(ROOT/'local/assets'/row['source']).read_bytes()
        if sha(data)!=row['sha256'] or native['name']!=name:raise ValueError('Changed PSS asset')
        ads,pts=private_stream(data)
        pcm=subprocess.run([ff,'-v','error','-xerror','-f','ads','-i','pipe:0','-map','0:a:0',
                            '-c:a','pcm_s16le','-f','s16le','pipe:1'],input=ads,capture_output=True,check=True).stdout
        if sha(pcm)!=row['pcm_sha256'] or pts!=row['first_audio_pts']:raise ValueError('Changed ADS payload')
        offset=row['delta_pts']
        audio=max(0,(offset*8+7)//15)
        video=max(0,(-offset*8+7)//15)
        clip=clips['unique_members'][records[name]['members'][0]['sha256']]
        samples=(clip['frames']*48000*clip['fps_den']+clip['fps_num']-1)//clip['fps_num']
        end=max(audio+len(pcm)//4,video+samples)
        size=(end+799)//800*800
        expected=bytes(audio*4)+pcm+bytes((size-audio)*4-len(pcm))
        if (native['audio_start'],native['video_start'],native['samples'],native['sha256'])!=(audio,video,size,sha(expected)):
            raise ValueError('Original movie PCM timeline diverged: '+name)
    now=datetime.now(timezone.utc)
    path=d/f'movie-audio-timeline-{now:%Y%m%d-%H%M%S}.json'
    path.write_text(json.dumps(dict(build=build['output_sha256'],cases=output,source_report_sha256=sha(sources.read_bytes())),
                               indent=2)+'\n',encoding='utf-8')
    print(json.dumps(dict(cases=len(output),stereo_frames=sum(v['samples'] for v in output),report=str(path))))


if __name__=='__main__':main()
