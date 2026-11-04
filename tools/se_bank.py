"""Source-bound SSDVDAT SE extraction; offline PCM is not a SPU2 mix capture.

The bank can contain two stored ADPCM streams while its raw playback stereo bit
is clear. Keep both streams and expose that disagreement; never guess routing.
"""
from __future__ import annotations

import argparse
from array import array
from collections import Counter
from fractions import Fraction
import io
import json
import math
from pathlib import Path
import re
import struct
import subprocess
import sys
import wave

from scenario_resources import ROOT, require, sha
from decode_scenario_resources import write_identical_or_new
from vm_handlers import Image

BANK_PATH = 'SOUND/SSDVDAT/se.dat'
RECORD_SIZE = 56
HEADER_SIZE = 57344
MAX_RECORDS = 1000  # original 0x1D1BF8, not the whole 0xE000 read allocation
DEFAULT_IDS = ('101039', '104036', '105016', '311015', '311016', '311017',
               '313008', '313070', '314006', '314009', '316004', '421089',
               '499013', '532019', '537002', '599012')
SOURCES = {
    'vag_demuxer': 'https://github.com/FFmpeg/FFmpeg/blob/n7.1/libavformat/vag.c',
    'spu2_pitch_and_loop': 'https://github.com/PCSX2/pcsx2/blob/master/pcsx2/SPU2/Mixer.cpp',
    'spu2_native_rate': 'https://github.com/PCSX2/pcsx2/blob/master/pcsx2/SPU2/spu2.h',
}


def parse_bank(data: bytes) -> list[dict]:
    require(len(data) >= HEADER_SIZE, 'Truncated SE header')
    rows, names, extents = [], set(), []
    for i in range(MAX_RECORDS):
        at = i * RECORD_SIZE
        raw = data[at:at + RECORD_SIZE]
        if not raw[0] & 0x80:  # original index-count termination rule
            break
        name = raw[40:46].decode('ascii')
        require(re.fullmatch(r'[0-9]{6}', name) is not None and raw[46] == 0,
                'Invalid SE identifier')
        require(name not in names, 'Duplicate SE identifier')
        require(not rows or rows[-1]['name'] < name, 'SE index is not sorted')
        names.add(name)
        words = struct.unpack_from('<10I', raw)
        offset, allocated = words[1] * 2048, words[2] * 2048
        total, stride = words[3] * 2, words[4] * 2
        require(offset >= HEADER_SIZE and allocated > 0 and
                offset + allocated <= len(data), 'SE sector bounds invalid')
        require(0 < stride <= total <= allocated and stride % 16 == total % 16 == 0,
                'Invalid SPU halfword sizes')
        channels = total // stride
        tail = total - channels * stride
        require(channels in (1, 2) and tail in (0, 16, 32, 48),
                'Unrecognized channel/padding layout')
        require(data[offset + channels * stride:offset + total] == b'\xff' * tail,
                'Unexplained SPU allocation padding')
        pitch, volume = struct.unpack_from('<HH', raw, 36)
        require(0 < pitch <= 4095, 'Unsupported zero/out-of-range original base pitch')
        rate = Fraction(48000 * pitch, 4096)
        row = dict(name=name, record_offset=at, record_sha256=sha(raw), raw_hex=raw.hex(),
                   offset=offset, sector_count=words[2], allocation_size=allocated,
                   allocation_sha256=sha(data[offset:offset + allocated]),
                   spu_allocation_bytes=total, stored_stream_bytes=stride,
                   stored_stream_count=channels, padding_bytes=tail,
                   raw_playback_flags=raw[3], raw_stereo_flag=bool(raw[3] & 0x80),
                   raw_loop_flag=bool(raw[3] & 0x10), base_pitch=pitch,
                   base_sample_rate=dict(numerator=rate.numerator, denominator=rate.denominator),
                   adsr1=words[8] & 0xffff, adsr2=words[8] >> 16,
                   base_volume=volume, raw_route_bytes=list(raw[54:56]))
        row['routing_status'] = ('single-stored-stream' if channels == 1 else
                                 'two-stored-streams-playback-routing-unverified')
        rows.append(row)
        extents.append((offset, offset + allocated))
    require(bool(rows), 'Empty SE bank')
    require(all(a[1] <= b[0] for a, b in zip(sorted(extents), sorted(extents)[1:])),
            'Overlapping SE allocations')
    return rows


def inspect_stream(data: bytes, loop_expected: bool) -> dict:
    """Validate stored blocks; first END bounds audible first-pass samples.

    A trailing 0x07/0x77 sentinel is retained as source, not appended to playback.
    Loop positions are zero-based sample indexes; end is exclusive.
    """
    require(len(data) >= 16 and len(data) % 16 == 0, 'Incomplete ADPCM block')
    ends, starts, flags = [], [], Counter()
    for at in range(0, len(data), 16):
        header, flag = data[at:at + 2]
        require(header >> 4 <= 4 and header & 15 <= 12, 'Invalid ADPCM predictor/shift')
        require(flag <= 7, 'Invalid ADPCM flag bits')
        flags[flag] += 1
        if flag & 1:
            ends.append(at)
        if flag & 4:
            starts.append(at)
    require(bool(ends), 'Missing ADPCM END')
    end = ends[0]
    looping = bool(data[end + 1] & 2)
    require(looping == loop_expected, 'Bank loop flag disagrees with ADPCM END')
    starts_before_end = [x for x in starts if x <= end]
    if looping:
        require(len(starts_before_end) == 1, 'Missing or ambiguous loop start')
        require(end + 16 == len(data), 'Unexplained data after looping END')
    else:
        tail = data[end + 16:]
        require(tail in (b'', b'\0\x07' + b'\x77' * 14),
                'Unexplained data after one-shot END')
    play_bytes = end + 16
    loop_start = starts_before_end[0] // 16 * 28 if looping else None
    return dict(stored_sha256=sha(data), stored_size=len(data),
                play_bytes=play_bytes, play_sha256=sha(data[:play_bytes]),
                sample_count=play_bytes // 16 * 28,
                loop=dict(enabled=looping, start_sample=loop_start,
                          end_sample_exclusive=play_bytes // 16 * 28 if looping else None,
                          original_start_block_byte=starts_before_end[0] if looping else None,
                          original_end_block_byte=end),
                flag_counts={str(k): v for k, v in sorted(flags.items())},
                retained_post_end_bytes=len(data) - play_bytes)


def vag_container(adpcm: bytes, sample_rate: int, name: str) -> bytes:
    require(sample_rate > 0 and re.fullmatch('[0-9]{6}', name) is not None,
            'Invalid derived VAG metadata')
    require(len(adpcm) > 0 and len(adpcm) % 16 == 0, 'Invalid VAG block size')
    header = bytearray(0x30)
    struct.pack_into('>4sIIII', header, 0, b'VAGp', 0x20, 0, len(adpcm), sample_rate)
    header[32:32 + len(name)] = name.encode('ascii')
    return bytes(header) + adpcm


def pcm_wave(pcm: bytes, sample_rate: int, channels: int, loop: dict) -> bytes:
    require(channels in (1, 2) and len(pcm) % (channels * 2) == 0, 'Invalid PCM data')
    output = io.BytesIO()
    with wave.open(output, 'wb') as writer:
        writer.setnchannels(channels)
        writer.setsampwidth(2)
        writer.setframerate(sample_rate)
        writer.writeframes(pcm)
    data = bytearray(output.getvalue())
    if loop['enabled']:
        start, stop = loop['start_sample'], loop['end_sample_exclusive']
        require(0 <= start < stop <= len(pcm) // (channels * 2), 'WAV loop out of bounds')
        # RIFF smpl uses an inclusive end. The extracted loop interval is half-open.
        smpl = struct.pack('<15I', 0, 0, round(1e9 / sample_rate), 60, 0, 0, 0, 1, 0,
                           0, 0, start, stop - 1, 0, 0)
        data += b'smpl' + struct.pack('<I', len(smpl)) + smpl
        struct.pack_into('<I', data, 4, len(data) - 8)
    return bytes(data)


def pcm_stats(pcm: bytes) -> dict:
    values = array('h')
    values.frombytes(pcm)
    if sys.byteorder != 'little':
        values.byteswap()
    require(bool(values), 'Empty PCM decode')
    peak = max(abs(x) for x in values)
    rms = math.sqrt(sum(x * x for x in values) / len(values))
    return dict(peak_sample=peak, rms_dbfs=20 * math.log10(rms / 32768) if rms else None,
                nonzero_samples=sum(x != 0 for x in values), pcm_sha256=sha(pcm))


def decode(root=ROOT, ids=DEFAULT_IDS) -> dict:
    root = Path(root).resolve()
    source = root / 'local/assets' / BANK_PATH
    bank = source.read_bytes()
    manifest = json.loads((root / 'analysis/fad_manifest.json').read_text(encoding='utf-8'))
    records = next(x['records'] for x in manifest['archives'] if x['name'] == 'DISC.FAD')
    matches = [x for x in records if x.get('path') == BANK_PATH]
    require(len(matches) == 1 and sha(bank) == matches[0]['sha256'] and
            len(bank) == matches[0]['size'], 'SE bank differs from FAD identity')
    rows = parse_bank(bank)
    selected = {r['name']: r for r in rows}
    require(len(ids) == len(set(ids)) and all(x in selected for x in ids), 'Invalid selected SE IDs')
    im = Image((root / 'local/extracted/SLPM_664.52').read_bytes())
    output = root / 'captures/derived/opening-audio'
    output.mkdir(parents=True, exist_ok=True)
    require(output.resolve().is_relative_to(root), 'Output escapes project')
    require(not any(p.is_symlink() or (hasattr(p, 'is_junction') and p.is_junction())
                    for p in [output, *output.parents]), 'Linked output directory')
    ffmpeg = root / 'local/dependencies/imageio_ffmpeg/binaries/ffmpeg-win-x86_64-v7.1.exe'
    report = dict(evidence_id='SE-BANK-001', status='offline-source-decoding-not-runtime-capture',
                  source_path=BANK_PATH, source_size=len(bank), source_sha256=sha(bank),
                  elf_sha256=im.sha256, record_count=len(rows),
                  stored_stream_counts=dict(Counter(str(r['stored_stream_count']) for r in rows)),
                  ffmpeg_sha256=sha(ffmpeg.read_bytes()), primary_sources=SOURCES,
                  native_audio_mix_verified=False, entries={},
                  evidence_windows=[im.region(a, b) for a, b in
                                    [(0x1d1bcc, 0x1d1c18), (0x1d1f9c, 0x1d2000),
                                     (0x1d24dc, 0x1d2534), (0x1d25f8, 0x1d2610),
                                     (0x1d3504, 0x1d3530), (0x1d3890, 0x1d3940)]])
    for name in ids:
        row = dict(selected[name])
        rate = row['base_sample_rate']
        require(rate['denominator'] == 1, 'Fractional base sample rate requires explicit adapter')
        sample_rate = rate['numerator']
        channels, pcms = [], []
        for c in range(row['stored_stream_count']):
            start = row['offset'] + c * row['stored_stream_bytes']
            raw = bank[start:start + row['stored_stream_bytes']]
            info = inspect_stream(raw, row['raw_loop_flag'])
            stem = f'{name}.stream-{c}'
            raw_path, vag_path, wav_path = [output / f'{stem}.{ext}' for ext in ('adpcm', 'vag', 'wav')]
            write_identical_or_new(raw_path, raw)
            write_identical_or_new(vag_path, vag_container(raw[:info['play_bytes']], sample_rate, name))
            command = [str(ffmpeg), '-hide_banner', '-nostdin', '-loglevel', 'error',
                       '-xerror', '-err_detect', 'explode', '-i', str(vag_path),
                       '-map', '0:a:0', '-c:a', 'pcm_s16le', '-f', 's16le', '-']
            run = subprocess.run(command, capture_output=True, timeout=60)
            stderr = run.stderr.decode('utf-8', errors='replace')
            require(run.returncode == 0 and not stderr.strip(), f'Strict ADPCM decode failed: {name}: {stderr}')
            require(len(run.stdout) == info['sample_count'] * 2, 'Decoded sample count mismatch')
            pcms.append(run.stdout)
            wav = pcm_wave(run.stdout, sample_rate, 1, info['loop'])
            write_identical_or_new(wav_path, wav)
            info.update(stored_stream_index=c, bank_offset=start, sample_rate=sample_rate,
                        duration_seconds=info['sample_count'] / sample_rate,
                        adpcm_path=raw_path.relative_to(root).as_posix(),
                        vag_path=vag_path.relative_to(root).as_posix(), vag_sha256=sha(vag_path.read_bytes()),
                        wav_path=wav_path.relative_to(root).as_posix(), wav_sha256=sha(wav),
                        decode_exit_code=run.returncode, decode_stderr=stderr, **pcm_stats(run.stdout))
            channels.append(info)
        row['streams'] = channels
        if len(pcms) == 2:
            require(len(pcms[0]) == len(pcms[1]) and channels[0]['loop'] == channels[1]['loop'],
                    'Stored stream lengths/loop points disagree')
            # A preservation export, not an assertion of source left/right routing.
            interleaved = bytearray(len(pcms[0]) * 2)
            for i in range(0, len(pcms[0]), 2):
                interleaved[2*i:2*i+2] = pcms[0][i:i+2]
                interleaved[2*i+2:2*i+4] = pcms[1][i:i+2]
            wav = pcm_wave(bytes(interleaved), sample_rate, 2, channels[0]['loop'])
            target = output / f'{name}.stored-channels.wav'
            write_identical_or_new(target, wav)
            row['two_channel_preservation_wav'] = dict(path=target.relative_to(root).as_posix(),
                                                      sha256=sha(wav), runtime_routing_verified=False)
        report['entries'][name] = row
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--ids', nargs='+', default=DEFAULT_IDS)
    args = parser.parse_args()
    report = decode(args.root, args.ids)
    target = args.root / 'analysis/se_bank.json'
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(report=str(target), records=report['record_count'],
                          decoded_entries=len(report['entries']),
                          decoded_streams=sum(len(x['streams']) for x in report['entries'].values()))))


if __name__ == '__main__':
    main()
