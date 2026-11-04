"""Compare recovered native functions with recorded original-instruction execution."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def number(value) -> int:
    if isinstance(value, int):
        return value
    text = str(value).split(':')[-1]
    return int(text, 16) if text.startswith('0x') or any(c in text.lower() for c in 'abcdef') else int(text, 10)


def raw(segment) -> bytes:
    return bytes.fromhex(segment['hex'].removeprefix('0x'))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def request(case: dict) -> tuple[bytes, list[dict], list[str]]:
    state = case['input']
    registers = state['registers']
    # Guest ABI stack writes are recorded by the instruction oracle, but C++
    # uses its host stack. Exclude only explicitly named stack ranges and record
    # that exclusion; compare every other supplied game-state memory range.
    observed, excluded = [], []
    for segment in case['output']['memory']:
        if segment.get('name', segment.get('role')) == 'stack':
            excluded.append('stack')
        else:
            observed.append(segment)
    payload = bytearray(b'KX3I')
    payload += struct.pack('<IIIQQQ', 2, number(case['function_address']), number(registers['a0']) & 0xffffffff,
                           number(registers.get('a1', 0)) & 0xffffffffffffffff,
                           number(registers.get('a2', 0)) & 0xffffffffffffffff,
                           number(registers.get('a3', 0)) & 0xffffffffffffffff)
    payload += struct.pack('<I', len(state['memory']))
    for segment in state['memory']:
        data = raw(segment)
        payload += struct.pack('<II', number(segment['address']), len(data)) + data
    payload += struct.pack('<I', len(observed))
    for segment in observed:
        payload += struct.pack('<II', number(segment['address']), len(raw(segment)))
    return bytes(payload), observed, excluded


def response(data: bytes) -> tuple[int, list[tuple[int, bytes]]]:
    if len(data) < 20 or data[:4] != b'KX3O':
        raise ValueError('Missing native probe response header')
    version, value, count = struct.unpack_from('<IQI', data, 4)
    if version != 1:
        raise ValueError('Unknown native probe response version')
    offset = 20
    segments = []
    for _ in range(count):
        address, length = struct.unpack_from('<II', data, offset)
        offset += 8
        if length > len(data) - offset:
            raise ValueError('Incomplete native response segment')
        segments.append((address, data[offset:offset + length]))
        offset += length
    if offset != len(data):
        raise ValueError('Trailing native response bytes')
    return value, segments


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('oracle_dir', type=Path)
    parser.add_argument('--probe', type=Path, default=ROOT / 'local/pc-core/core_probe.exe')
    args = parser.parse_args()
    oracle = args.oracle_dir.resolve()
    manifest = json.loads((oracle / 'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('status') not in ('completed', 'oracle_completed', 'success'):
        raise ValueError(f'Oracle is not complete: {manifest.get("status")}')
    cases_path = oracle / 'cases.jsonl'
    cases = [json.loads(line) for line in cases_path.read_text(encoding='utf-8').splitlines() if line.strip()]
    if not cases:
        raise ValueError('An empty oracle is not a successful verification')
    build_path = args.probe.with_suffix('.build.json')
    build = json.loads(build_path.read_text(encoding='utf-8'))
    probe_digest = sha(args.probe)
    if build['output_sha256'] != probe_digest:
        raise ValueError('Probe does not match its recorded build')
    if any(sha(Path(p)) != digest for p, digest in build['sources'].items()):
        raise ValueError('Native sources changed after the probe build')
    run_id = f'{time.strftime("%Y%m%d-%H%M%S")}-{uuid.uuid4().hex[:6]}'
    fixtures = ROOT / 'local/pc-core/diff' / run_id
    fixtures.mkdir(parents=True, exist_ok=False)
    results = []
    per_function = Counter()
    started = time.time()
    prepared = [request(case) for case in cases]
    batch = bytearray(b'KX3B') + struct.pack('<II', 1, len(prepared))
    for payload, _, _ in prepared:
        batch += struct.pack('<I', len(payload)) + payload
    input_path, output_path = fixtures / 'batch.in', fixtures / 'batch.out'
    input_path.write_bytes(batch)
    execution = subprocess.run([str(args.probe.resolve()), '--batch', str(input_path), str(output_path)],
                               capture_output=True, text=True, timeout=300,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    if execution.returncode not in (0, 1) or not output_path.exists():
        raise ValueError(f'Native batch failed: {execution.returncode}: {execution.stderr}')
    batch_output = output_path.read_bytes()
    if len(batch_output) < 12 or batch_output[:4] != b'KX3R' or struct.unpack_from('<II', batch_output, 4) != (1, len(cases)):
        raise ValueError('Invalid native batch response')
    responses, offset = [], 12
    for _ in cases:
        status, length = struct.unpack_from('<II', batch_output, offset)
        offset += 8
        if length > len(batch_output) - offset:
            raise ValueError('Truncated native batch response')
        responses.append((status, batch_output[offset:offset + length]))
        offset += length
    if offset != len(batch_output):
        raise ValueError('Trailing native batch response')
    for index, case in enumerate(cases):
        identifier = case.get('id', str(index))
        outcome = dict(id=identifier, function_address=case['function_address'], passed=False)
        try:
            _, observed, excluded = prepared[index]
            status, payload = responses[index]
            outcome.update(native_exit=status, excluded_guest_abi_ranges=excluded)
            if status != 0:
                raise ValueError(f'Native execution failed: {payload.decode("utf-8", errors="replace")}')
            value, actual = response(payload)
            if case['return_defined']:
                expected = number(case['output']['registers']['v0']) & 0xffffffffffffffff
                outcome['return_bits_match'] = value == expected
                if value != expected:
                    outcome['return_mismatch'] = dict(expected=f'0x{expected:016x}', actual=f'0x{value:016x}')
            else:
                outcome['return_bits_match'] = None
            if len(actual) != len(observed):
                raise ValueError('Native observation count differs from requested ranges')
            differences = []
            compared = 0
            for segment, (address, data) in zip(observed, actual):
                expected = raw(segment)
                if address != number(segment['address']) or len(data) != len(expected):
                    raise ValueError('Native observation range differs from request')
                compared += len(expected)
                for i, (want, got) in enumerate(zip(expected, data)):
                    if want != got:
                        differences.append(dict(address=f'0x{address+i:08x}', expected=want, actual=got,
                                                segment=segment.get('name', segment.get('role'))))
            outcome.update(memory_bytes_compared=compared, memory_difference_count=len(differences),
                           first_memory_differences=differences[:16])
            outcome['passed'] = not differences and outcome['return_bits_match'] is not False
        except (OSError, ValueError, KeyError, struct.error, subprocess.TimeoutExpired) as error:
            outcome['error'] = str(error)
        results.append(outcome)
        per_function[outcome['function_address']] += int(outcome['passed'])
    report = dict(schema=1, authority='Recovered C++ versus Ghidra/SLEIGH execution of original ELF instructions',
                  oracle_directory=str(oracle), oracle_cases_sha256=sha(cases_path),
                  oracle_manifest_sha256=sha(oracle / 'manifest.json'), probe=str(args.probe.resolve()),
                  probe_sha256=probe_digest, probe_build_manifest=build, source_sha256=sha(ROOT / 'local/extracted/SLPM_664.52'),
                  native_sources={str(Path(p).relative_to(ROOT)): digest for p, digest in build['sources'].items()},
                  cases=len(results), passed=sum(r['passed'] for r in results),
                  all_passed=all(r['passed'] for r in results), per_function_passed=dict(per_function),
                  elapsed_seconds=round(time.time() - started, 3), results=results,
                  limitations=['Oracle uses Ghidra R5900 SLEIGH, not PCSX2 or physical PS2 execution.',
                               'Only recorded inputs, defined return values, and supplied game-state memory ranges are compared.',
                               'Guest ABI stack and scratch-register clobbers are outside the native C++ API.',
                               'No complete-game correctness or hardware/media behavior is established.'])
    report['build_stable_during_run'] = sha(args.probe) == probe_digest and all(
        sha(Path(p)) == digest for p, digest in build['sources'].items())
    report['all_passed'] = report['all_passed'] and report['build_stable_during_run']
    report_path = ROOT / 'analysis/native-core' / f'diff-{run_id}.json'
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('cases', 'passed', 'all_passed', 'per_function_passed', 'elapsed_seconds')}, ensure_ascii=False))
    print(str(report_path))
    if not report['all_passed']:
        print(json.dumps([r for r in results if not r['passed']][:3], ensure_ascii=False))
    return 0 if report['all_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
