"""Recheck the frozen 2026-10-30 evidence; never rerun or invent oracle results.

This is deliberately a dated checkpoint, not a glob of every historical pass.
Run after resuming to detect changes that invalidate this particular checkpoint.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'analysis/native-core/final-verification-20261030.json'
ELF_SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'
STANDARD = [
    ('readers', '112621-43d54d', 470),
    ('strings', '112622-5653ce', 56),
    ('history', '112621-762029', 809),
    ('tables', '112622-20473a', 460),
    ('libc', '112623-014f75', 292),
    ('choice_leaves', '112623-4230fa', 154),
    ('dispatch', '112624-75c982', 355),
    ('manager', '112625-8bfd63', 300),
    ('media_command', '112624-763324', 264),
    ('enhanced_mmi_libc', '112626-b1ae16', 248),
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha(path: str | Path) -> str:
    with (ROOT / path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def load(path: str | Path) -> dict:
    return json.loads((ROOT / path).read_text(encoding='utf-8-sig'))


def check_hash(path: str | Path, expected: str) -> None:
    require(sha(path) == expected.lower(), f'Fingerprint changed: {path}')


def sources(hashes: dict) -> None:
    for path, expected in hashes.items():
        check_hash(path, expected)


def reference(path: str | Path) -> dict:
    path = ROOT / path
    return {'path': path.relative_to(ROOT).as_posix(), 'sha256': sha(path)}


def main() -> None:
    check_hash('local/extracted/SLPM_664.52', ELF_SHA)
    build_path = 'local/pc-core/core_probe.build.json'
    build = load(build_path)
    sources(build['sources'])
    for prefix in ['output', 'contracts', 'walker', 'index', 'state_call']:
        path_key = 'output' if prefix == 'output' else prefix + '_output'
        hash_key = 'output_sha256' if prefix == 'output' else prefix + '_sha256'
        check_hash(build[path_key], build[hash_key])
    check_hash('local/pc-core/media_active_contracts.exe', build['media_contracts_sha256'])
    require(build['contracts_passed'] and build['media_contracts_passed'], 'Host contracts failed')

    rows = []
    for name, suffix, count in STANDARD:
        path = f'analysis/native-core/diff-20261030-{suffix}.json'
        report = load(path)
        require(report['all_passed'] and report['build_stable_during_run'], name + ': not passed/stable')
        require(report['cases'] == report['passed'] == count, name + ': case count changed')
        require(len(report['results']) == count and all(r['passed'] for r in report['results']), name + ': failed row')
        require(report['probe_build_manifest'] == build, name + ': different build')
        normalized_sources = {str((ROOT / p).resolve()): h for p, h in report['native_sources'].items()}
        require(normalized_sources == build['sources'], name + ': different sources')
        require(report['probe_sha256'] == build['output_sha256'], name + ': different binary')
        oracle = Path(report['oracle_directory'])
        check_hash(oracle / 'manifest.json', report['oracle_manifest_sha256'])
        check_hash(oracle / 'cases.jsonl', report['oracle_cases_sha256'])
        rows.append({'name': name, 'passed': count, **reference(path)})

    for name, suffix, count in [('control_transfer', '112704-a087cf', 54), ('choice_transfer', '112654-2e6024', 33)]:
        path = f'analysis/native-core/state-calls-20261030-{suffix}.json'
        report = load(path)
        require(report['build'] == build, name + ': different build')
        require(report['all_passed'] and report['cases'] == report['passed'] == count, name + ': failed')
        require(len(report['results']) == count and all(r['passed'] for r in report['results']), name + ': failed row')
        oracle = Path(report['oracle'])
        manifest = load(oracle / 'manifest.json')
        require(manifest == report['oracle_manifest'], name + ': oracle changed')
        check_hash(oracle / 'cases.jsonl', manifest['cases_sha256'])
        check_hash(oracle / 'input-plan.json', manifest['source_plan_sha256'])
        rows.append({'name': name, 'passed': count, **reference(path)})

    readback_path = 'analysis/native-core/choice-readback-diff.json'
    readback = load(readback_path)
    require(readback['status'] == 'passed' and readback['cases'] == readback['passed'] == 14, 'Readback failed')
    require(len(readback['rows']) == 14 and all(r['passed'] for r in readback['rows']), 'Readback row failed')
    sources(readback['source_sha256'])
    check_hash('local/pc-core/choice_readback_probe.exe', readback['executable_sha256'])
    check_hash(Path(readback['oracle']) / 'manifest.json', readback['oracle_manifest_sha256'])
    rows.append({'name': 'readback_up', 'passed': 14, 'separate_probe': True, **reference(readback_path)})

    choice_path = 'analysis/native-core/choice-pipeline-slot7.json'
    choice = load(choice_path)
    sources(choice['source_sha256'])
    check_hash('local/pc-core/choice_pipeline_test.exe', choice['executable_sha256'])
    require(choice['result']['status'] == 'passed' and choice['result']['checks'] == 74, 'Choice contracts failed')

    images_path = 'analysis/native-core/script-images-20261030-112730-ac84c4.json'
    images = load(images_path)
    require(images['status'] == 'passed' and images['build'] == build, 'Script image build/results differ')
    require(sum(s['source_symbols_verified'] for s in images['scripts']) == 11543, 'Script label total changed')
    require(sum(s['original_runtime_label_ids_verified'] for s in images['scripts']) == 6566, 'Runtime label total changed')
    for script in images['scripts']:
        check_hash(script['index'], script['index_sha256'])
        require(script['allocation_failure_rolled_back'], 'Script allocation rollback failed')

    media_path = 'analysis/native-core/media-state-20261030-112802-f3d51c.json'
    media = load(media_path)
    media_build_path = 'local/pc-core/media_state_probe.build.json'
    media_build = load(media_build_path)
    require(media['status'] == 'passed' and media['build'] == media_build, 'Media build/results differ')
    sources(media_build['sources'])
    check_hash(media_build['output'], media_build['output_sha256'])
    trace = media['trace']
    require(trace[0]['passed'], 'Missing asset rollback failed')
    require(trace[1]['opcode'] == 0x72 and trace[1]['prepared_generations'] == 1 and trace[1]['current_generation'] == 0, 'Media preload result changed')
    require(trace[2]['actual_rgba_bytes'] == 1146880, 'Real decoded image missing')
    require(trace[3]['opcode'] == 0x40 and trace[3]['full_ram_rolled_back'] and trace[3]['prepared_state_unchanged'], 'Unported handler rollback failed')

    report = {
        'schema': 1,
        'checked_utc': datetime.now(timezone.utc).isoformat(),
        'status': 'frozen_evidence_verified',
        'source_elf_sha256': ELF_SHA,
        'verifier': reference(Path(__file__)),
        'core_build': reference(build_path),
        'core_probe_sha256': build['output_sha256'],
        'standard_differential_cases': 3408,
        'all_differential_cases': sum(r['passed'] for r in rows),
        'differentials': rows,
        'choice_contracts': {'checks': 74, **reference(choice_path)},
        'host_core_contracts_passed': build['contracts_passed'],
        'media_active_contracts_passed': build['media_contracts_passed'],
        'script_images': reference(images_path),
        'media_build': reference(media_build_path),
        'actual_media_preload': reference(media_path),
        'limitations': [
            'This verifies saved evidence and current fingerprints; it does not rerun the tests.',
            'These are sampled instruction comparisons, not a percentage of port completion.',
            'Oracles execute original ELF instructions through Ghidra/SLEIGH; specified cases use six isolated MMI userops. They are not PS2 hardware tests.',
            'Readback uses a separate executable with matching frozen module hashes.',
            'Full-state comparisons cover observed objects and every original persistent write, not arbitrary extra native writes outside those ranges.',
            'Media 72 only preloads a real image. It does not activate the renderer or play audio.',
            'The original-state fixture is for testing; cold game boot is not complete.',
            'The Windows game, complete saves/presentation, GPU UI, full text pipeline, translations and proofreading are not finished.',
        ],
        'next_blocking_entry': '0x00127240 (opcode 0x40), then original manager text path 0x001126E0',
    }
    require(report['all_differential_cases'] == 3509, 'Unexpected aggregate count')
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'differential_cases': report['all_differential_cases'], 'output': str(OUT)}))


if __name__ == '__main__':
    main()
