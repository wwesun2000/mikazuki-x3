"""Prepare editorial review packets across both Chinese manuscript sources."""
import argparse
import json
import re

import zh_story_batch as story


def manuscript():
    rows = []
    for path in sorted((story.BASE / 'groups').glob('*.spec.json')):
        spec = story.read(path)
        for group in spec['groups']:
            rows.append(dict(id=group['id'], program=spec['program'], selector=spec['selector'],
                offset=group['primary_offsets'][0], label=[group['label']], ja=group['source_text'],
                zh=group['zh-Hans'], origin=str(path.relative_to(story.ROOT)), kind='legacy-story'))
    for path in sorted(story.DRAFTS.glob('sn*/block-*.json')):
        for group in story.read(path)['entries'].values():
            name, selector, offset = group['id'].split(':')
            rows.append(dict(id=group['id'], program=name, selector=int(selector, 16), offset=int(offset, 16),
                label=group['label'], ja=group['ja'], zh=group['zh'],
                origin=str(path.relative_to(story.ROOT)), kind=group.get('kind', 'story'),
                before_live_name=group.get('before_live_name'), reused_from=group.get('reused_from')))
    rows.sort(key=lambda r: (r['program'], r['selector'], r['offset']))
    if len({r['id'] for r in rows}) != len(rows):
        raise ValueError('Duplicate manuscript identity')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packet', type=story.Path)
    parser.add_argument('--program', choices=('sn2', 'sn4', 'sn4g'))
    parser.add_argument('--selector', type=int)
    parser.add_argument('--label', help='Regular expression over original source labels')
    parser.add_argument('--match', help='Regular expression over Japanese and Chinese text')
    parser.add_argument('--start', type=int, default=0)
    parser.add_argument('--count', type=int, default=120)
    args = parser.parse_args()
    rows = manuscript()
    pattern = re.compile(args.match) if args.match else None
    label_pattern = re.compile(args.label) if args.label else None
    selected = []
    for i, row in enumerate(rows):
        if args.program and row['program'] != args.program:
            continue
        if args.selector is not None and row['selector'] != args.selector:
            continue
        if label_pattern and not any(label_pattern.search(label) for label in row['label']):
            continue
        if row['kind'] not in ('story', 'legacy-story', 'system-text'):
            continue
        if pattern and not pattern.search(row['ja'] + '\n' + row['zh']):
            continue
        context = []
        for j in (i - 1, i + 1):
            if 0 <= j < len(rows):
                neighbor = rows[j]
                if neighbor['program'] == row['program'] and neighbor['selector'] == row['selector']:
                    context.append({key: neighbor[key] for key in ('id', 'label', 'ja', 'zh')})
        selected.append(dict(**row, text_sha256=story.sha(row['zh'].encode('utf-8')),
                             neighboring_static_records=context))
    output = dict(status='unreviewed', release_allowed=False,
        context_note='Neighbors are static storage order, not an asserted execution path.',
        total_matches=len(selected), start=args.start, rows=selected[args.start:args.start + args.count])
    args.packet.parent.mkdir(parents=True, exist_ok=True)
    args.packet.write_text(json.dumps(output, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Total matches', len(selected))
    for i, row in enumerate(output['rows'], args.start + 1):
        print(f"{i} {row['id']} | {row['ja']}\n  {row['zh']}")
        if row.get('before_live_name'):
            print('  [Before original 0E name insertion]', row['before_live_name']['zh'])


if __name__ == '__main__':
    main()
