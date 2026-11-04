"""Read-only focused proper-name audit; does not rewrite translations or guest data."""
import json
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    sys.stdout.reconfigure(encoding='utf-8')
    cast = json.loads((ROOT / 'localization/full-source/groups/sn4g-cast-labels.spec.json').read_text(encoding='utf-8'))['groups']
    gloss = json.loads((ROOT / 'localization/glossary.json').read_text(encoding='utf-8'))['terms']
    terms = {g['source_text']: g['zh-Hans'] for g in cast[:13]}
    selected = ('真理', '俊夫', '美樹本', 'みどり', '篠崎みどり', '菱田喜代', '姫宮麗子', '権藤精作', '春子', '啓子', '夏美')
    terms.update({g['ja']: g['zh-Hans'] for g in gloss if g['ja'] in selected})
    entries = []
    for p in sorted((ROOT / 'localization/full-source/zh-Hans').glob('*/*.json')):
        entries.extend(json.loads(p.read_text(encoding='utf-8')).get('entries', {}).values())
    source = (ROOT / 'local/assets/SCENARIO/sn4g.sn4').read_bytes()
    elf = (ROOT / 'local/extracted/SLPM_664.52').read_bytes()
    defaults = []
    for address, expected in ((0x235e30, '透'), (0x235e38, '真理')):
        off = address - 0xff000
        raw = elf[off:elf.index(b'\0', off)]
        assert raw.decode('cp932') == expected
        defaults.append(dict(address=hex(address), cp932=raw.hex(), text=expected))
    for g in cast:
        off = g['primary_offsets'][0]
        raw = b'\x02' + g['source_text'].encode('cp932') + b'\x03'
        assert source[off:off + len(raw)] == raw, g['id']
    results = []
    for ja, zh in terms.items():
        hits = [e for e in entries if ja in e.get('ja', '')]
        missing = [e for e in hits if zh not in e.get('zh', '')]
        row = dict(ja=ja, zh=zh, source_occurrences=len(hits), without_literal_target=len(missing))
        results.append(row)
        print(f'{ja} => {zh}: {len(hits)} source occurrences; {len(missing)} without literal target')
        # These are review candidates, not automatic failures: pronouns, suffixes,
        # source-bound fragments and nickname forms legitimately differ.
        row['review_examples'] = [{k: e.get(k) for k in ('id', 'ja', 'zh')} for e in missing[:4]]
    report = dict(scope='NAME-UI-01 focused terminology audit; not full prose review',
                  manuscript_entries=len(entries), defaults=defaults, cast_source_labels_verified=len(cast),
                  elf_sha256=hashlib.sha256(elf).hexdigest(), scenario_sha256=hashlib.sha256(source).hexdigest(),
                  terms=results)
    if '--write-report' in sys.argv:
        path = ROOT / 'localization/review/name-ui-01.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
