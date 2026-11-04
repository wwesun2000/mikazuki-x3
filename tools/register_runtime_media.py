"""Archive the three completed original-game references and validate decoding.

Build/session specific. Originals are read only; archived files are created with
exclusive mode and any existing destination causes a stop before copying.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.capture_catalog import register, safe_path

ISO_SHA = '2a193cdbe97ba96faf0ad4d376a1d45b765aa99625895ff161f5102a5e85c95d'
ARCHIVE = ROOT / 'captures/runtime/original-20261030'
FFMPEG = ROOT / 'local/dependencies/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe'
FILES = [
    ('local/pcsx2/videos/Kamaitachi no Yoru 3_SLPM-66452_20261030001743.mp4',
     'runtime-video', 'Three-game selection menu and input troubleshooting reference; not a story demonstration.'),
    ('local/pcsx2/snaps/Kamaitachi no Yoru 3_SLPM-66452_20261030001642.png',
     'runtime-screenshot', 'Original Japanese title screen reference.'),
    ('local/pcsx2/snaps/Kamaitachi no Yoru 3_SLPM-66452_20261030002614.png',
     'runtime-screenshot', 'Original Japanese three-game selection screen reference.'),
]


def stamp(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def identity(path):
    before = path.stat()
    with path.open('rb') as handle:
        digest = hashlib.file_digest(handle, 'sha256').hexdigest()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError('Source is still changing: ' + path.name)
    return {'sha256': digest, 'size_bytes': after.st_size,
            'source_birthtime_utc': stamp(getattr(after, 'st_birthtime', after.st_ctime)),
            'source_mtime_utc': stamp(after.st_mtime),
            'source_mtime_ns': after.st_mtime_ns}


def probe_text(text):
    duration = re.search(r'Duration: (\d+):(\d+):(\d+(?:\.\d+)?)', text)
    seconds = (int(duration[1])*3600 + int(duration[2])*60 + float(duration[3])) if duration else None
    # Preserve original input stream lines as authoritative metadata evidence.
    input_text = text.split('Stream mapping:')[0]
    streams = [line.strip() for line in input_text.splitlines() if re.search(r'Stream #0:\d+.*(?:Video|Audio):', line)]
    video = next((s for s in streams if 'Video:' in s), '')
    audio = next((s for s in streams if 'Audio:' in s), '')
    dims = re.search(r'\b(\d{2,5})x(\d{2,5})\b', video)
    fps = re.search(r'([\d.]+) fps\b', video)
    sar = re.search(r'SAR ([^\s\]]+)', video)
    dar = re.search(r'DAR ([^\s\]]+)', video)
    return {'container_duration_seconds': seconds, 'input_stream_lines': streams,
            'video_codec': re.search(r'Video: ([^, ]+)', video)[1] if video else None,
            'video_width': int(dims[1]) if dims else None,
            'video_height': int(dims[2]) if dims else None,
            'video_fps_reported': float(fps[1]) if fps else None,
            'sample_aspect_ratio': sar[1] if sar else None,
            'display_aspect_ratio': dar[1] if dar else None,
            'audio_codec': re.search(r'Audio: ([^, ]+)', audio)[1] if audio else None,
            'audio_sample_rate_hz': int(re.search(r'(\d+) Hz', audio)[1]) if re.search(r'(\d+) Hz', audio) else None,
            'audio_channels_reported': 'stereo' if 'stereo' in audio else ('mono' if 'mono' in audio else None)}


def audio_quality_from_log(text, duration):
    def last(pattern):
        values=re.findall(pattern,text)
        return float(values[-1]) if values else None
    start=last(r'silence_start: ([\d.]+)')
    end=last(r'silence_end: ([\d.]+)')
    silence_duration=last(r'silence_duration: ([\d.]+)')
    full_silence=(start==0 and end is not None and duration is not None and abs(end-duration)<0.05)
    return {'method':'ffmpeg silencedetect threshold -60 dB, minimum 1 second; volumedetect',
            'mean_volume_db':last(r'mean_volume: (-?[\d.]+) dB'),
            'max_volume_db':last(r'max_volume: (-?[\d.]+) dB'),
            'silence_start_seconds':start,'silence_end_seconds':end,'silence_duration_seconds':silence_duration,
            'whole_audio_below_minus_60_db':full_silence,
            'editorial_assessment':'No useful audible game audio captured; retain as menu/input-troubleshooting reference.' if full_silence else 'Audio levels inspected; listening and sync review still needed.',
            'log_path':'analysis/runtime_original_20261030_audio.log'}


def main():
    planned=[]
    for relative,kind,description in FILES:
        source=safe_path(ROOT,relative)
        destination=safe_path(ROOT,ARCHIVE/source.name,must_exist=False)
        if destination.exists():raise FileExistsError('Refusing to overwrite existing archived media: '+str(destination))
        planned.append((source,destination,kind,description,identity(source)))
    ARCHIVE.mkdir(parents=True,exist_ok=True)
    records=[]
    for source,destination,kind,description,original in planned:
        with source.open('rb') as incoming,destination.open('xb') as outgoing:
            shutil.copyfileobj(incoming,outgoing,1024*1024)
            outgoing.flush();os.fsync(outgoing.fileno())
        current=identity(source);archived=identity(destination)
        if current!=original or archived['sha256']!=original['sha256'] or archived['size_bytes']!=original['size_bytes']:
            raise ValueError('Copy/source identity mismatch: '+source.name)
        records.append(dict(source_path=source.relative_to(ROOT).as_posix(),archive_path=destination.relative_to(ROOT).as_posix(),
                            kind=kind,description=description,**original,copy_sha256=archived['sha256']))
    video=next(row for row in records if row['kind']=='runtime-video')
    output_log=ROOT/'analysis/runtime_original_20261030_ffmpeg.log'
    progress_log=ROOT/'analysis/runtime_original_20261030_ffmpeg_progress.log'
    args=[str(FFMPEG),'-nostdin','-hide_banner','-loglevel','info','-xerror','-err_detect','explode',
          '-i',str(ROOT/video['archive_path']),'-map','0:v','-map','0:a?',
          '-progress','pipe:1','-nostats','-f','null','-']
    process=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=240,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    stderr=process.stderr.decode('utf-8','replace');stdout=process.stdout.decode('utf-8','replace')
    output_log.write_text(json.dumps({'command':args,'returncode':process.returncode},ensure_ascii=False)+'\n'+stderr,encoding='utf-8')
    progress_log.write_text(stdout,encoding='utf-8')
    progress={}
    for line in stdout.splitlines():
        if '=' in line:
            key,value=line.split('=',1);progress[key]=value
    metadata=probe_text(stderr)
    decode_success=process.returncode==0 and progress.get('progress')=='end'
    warnings=[line for line in stderr.splitlines() if any(k in line.lower() for k in ('error','warning','corrupt','invalid','non-monoton','conceal','damaged'))]
    video['media_metadata']=metadata
    video['decode_validation']={'all_video_and_audio_streams_mapped':True,'ffmpeg_returncode':process.returncode,
                                'completed':decode_success,'progress_last':progress,
                                'warning_error_lines':warnings,'log_path':output_log.relative_to(ROOT).as_posix(),
                                'progress_path':progress_log.relative_to(ROOT).as_posix(),
                                'quality_scope':'Decodability only. Does not prove useful gameplay, audio clarity, sync, clean input, or editorial quality.'}
    audio_args=[str(FFMPEG),'-nostdin','-hide_banner','-loglevel','info','-i',str(ROOT/video['archive_path']),
                '-map','0:a:0','-vn','-af','silencedetect=noise=-60dB:d=1,volumedetect','-f','null','-']
    audio_run=subprocess.run(audio_args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    audio_text=audio_run.stderr.decode('utf-8','replace')
    (ROOT/'analysis/runtime_original_20261030_audio.log').write_text(json.dumps({'command':audio_args,'returncode':audio_run.returncode})+'\n'+audio_text,encoding='utf-8')
    video['audio_quality']=audio_quality_from_log(audio_text,metadata['container_duration_seconds'])
    video['audio_quality']['ffmpeg_returncode']=audio_run.returncode
    for row in records:
        if row['kind']=='runtime-screenshot':
            with (ROOT/row['archive_path']).open('rb') as handle:header=handle.read(33)
            if header[:8]!=b'\x89PNG\r\n\x1a\n' or header[12:16]!=b'IHDR':raise ValueError('Unexpected PNG header')
            width,height,depth,color=struct.unpack_from('>IIBB',header,16)
            row['media_metadata']={'codec':'png','width':width,'height':height,'bit_depth':depth,'png_color_type':color,
                                   'validation':'PNG signature and IHDR inspected; no visual-quality guarantee'}
    settings={'emulator':'PCSX2','emulator_version':'2.8.2','game_serial':'SLPM-66452','game_crc':'0D03C0A3',
              'renderer':'Direct3D 12','gpu':'AMD Radeon(TM) Graphics','driver_version':'32.0.21045.16010',
              'internal_resolution':{'width':640,'height':448,'scale':1},'configured_display_aspect':'4:3',
              'window_mode':'windowed','language':'ja','settings_evidence':'Current task runtime observations supplied by parent agent; not inferred from media codec.',
              'filter_settings':'not independently recorded for this capture; do not infer upscaling/scanlines enabled'}
    for row in records:
        render_settings=dict(settings,encoded_media=row['media_metadata'])
        notes=('Original-emulator reference only; no native Windows port functionality demonstrated. '
               'Timestamp is original source file creation time in UTC, not an embedded recording-start timestamp. '
               'Source media preserved. No BIOS is copied. ')
        if row['kind']=='runtime-video':
            notes+='Static three-game selection menu plus input troubleshooting; not a story walkthrough. Full-stream decode '+('passed' if decode_success else 'did not pass')+'. Editorial quality and audio sync require review.'
            if row['audio_quality']['whole_audio_below_minus_60_db']:
                notes+=' Audio inspection: entire 438.826667-second audio stream is below -60 dB; maximum and mean reported -91 dB. No useful audible game audio captured. See analysis/runtime_original_20261030_audio.log.'
                render_settings['audio_capture_quality']=row['audio_quality']
        registration=register(ROOT,row['archive_path'],kind=row['kind'],status='captured',source_sha256=ISO_SHA,
                              source_asset_id='iso:'+ISO_SHA,recorded_at=row['source_birthtime_utc'],language='ja',
                              render_settings=render_settings,stage='original-emulator-reference',spoiler='none',
                              description=row['description'],notes=notes)
        row['catalog_registration']=registration
    report={'schema_version':1,'evidence_id':'RUNTIME-MEDIA-001','source_iso_sha256':ISO_SHA,
            'scope':'Original Japanese emulator reference; title and selection menu, including input troubleshooting; not native port or story playthrough.',
            'archive_policy':'Exclusive creation, no overwrite, originals retained, SHA-256 copied identity checked.',
            'capture_time_basis':'Original source filesystem creation time UTC; filename timestamp retained in source path; embedded timestamp not assumed.',
            'render_settings':settings,'files':records,
            'limitations':['Video decode validation is technical integrity only; recording may contain silence, failed inputs, long still sections, or other editorial issues.',
                           'No screen UI was operated, no source media edited, no active emulator log modified.',
                           'Screenshot dimensions are encoded image dimensions and can differ from internal 640x448 rendering.']}
    (ROOT/'analysis/runtime_media.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'archived_files':len(records),'video_metadata':metadata,'decode_completed':decode_success,
                      'decode_warnings':warnings,'screenshots':[r['media_metadata'] for r in records if r['kind']=='runtime-screenshot'],
                      'report':'analysis/runtime_media.json'},ensure_ascii=True))


if __name__=='__main__':main()
