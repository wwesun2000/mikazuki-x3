"""Audit the explicitly enhanced Ghidra MMI validation evidence (not a PS2 oracle)."""
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'analysis/ghidra/mmi-validation-v1'
SHA = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    assert digest(ROOT / 'local/extracted/SLPM_664.52') == SHA
    manifest = json.loads((OUT / 'manifest.json').read_text())
    assert manifest['status'] == 'mmi_validation_completed'
    assert manifest['original_ghidra_support'] is False
    assert manifest['independent_lane_vectors_passed'] == 3072
    cases = json.loads((OUT / 'cases.json').read_text())
    assert len(cases) == 275
    totals = {name: 0 for name in manifest['executed_userops']}
    covered = set()
    for case in cases:
        left, right = bytes.fromhex(case['a_hex']), bytes.fromhex(case['b_hex'])
        expected = 0
        for a, b in zip(left, right):
            expected = a - b
            if expected or not a:
                break
        assert case['status'] == 'passed' and case['actual'] == case['expected'] == expected
        covered.add((case['alignment'], case['length'], case['variant']))
        for name, count in case['userops'].items():
            totals[name] += count
    assert len(covered) == 275 and totals == manifest['executed_userops']
    assert all(totals[name] > 0 for name in totals if name != '_por')
    assert totals['_por'] == 0  # Do not report an instruction integration test for POR.
    sources_dir = ROOT / 'local/dependencies/rea-ps2/mmi-oracle-sources'
    sources = json.loads((sources_dir / 'sources.json').read_text())
    for source in sources:
        assert digest(sources_dir / source['file']) == source['sha256']
    archive = OUT / 'engine-sources'
    archive.mkdir(exist_ok=True)
    files = []
    for name in ('KamaitachiMmiUserops.java', 'ValidateKamaitachiMmi.java'):
        path = ROOT / 'tools/ghidra' / name
        copied = archive / name
        if not copied.exists():
            shutil.copyfile(path, copied)
        assert digest(path) == digest(copied)
        files.append({'path': str(path.relative_to(ROOT)), 'archive': str(copied.relative_to(ROOT)), 'sha256': digest(path)})
    language = ROOT / 'local/dependencies/ghidra-ee/ghidra_12.1.4_PUBLIC/Ghidra/Extensions/ghidra-emotionengine-reloaded/data/languages'
    report = {
        'schema': 1, 'status': 'passed', 'source_sha256': SHA,
        'strcmp_cases': len(cases), 'independent_lane_vectors_reported_by_java': 3072,
        'executed_userops': totals, 'total_userop_executions': sum(totals.values()),
        'cases_sha256': digest(OUT / 'cases.json'), 'manifest_sha256': digest(OUT / 'manifest.json'),
        'engine_sources': files, 'official_sources': sources,
        'language_sources': [{'path': str(p.relative_to(ROOT)), 'sha256': digest(p)} for p in [language / 'eecore.sinc', language / 'r5900.sla']],
        'limits': ['Explicit project oracle-engine extension, not original Ghidra MMI support',
                   'PCSX2 source semantics reviewed; no PCSX2 execution or physical PS2 differential test',
                   'POR has independent arithmetic vectors only; the other five execute in original strcmp',
                   'Other CALLOTHER operations still fail; no wildcard callback or game-function substitution',
                   'Unknown userops, hardware/MMIO, timing, exceptions and full EE ISA are not implemented'],
    }
    (OUT / 'audit.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'status': 'passed', 'strcmp_cases': 275, 'userop_executions': sum(totals.values())}))


if __name__ == '__main__':
    main()
