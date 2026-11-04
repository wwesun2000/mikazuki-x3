"""Count Chinese first-draft coverage once per original record, including ruby separately."""
from collections import Counter
from zh_story_batch import BASE, DRAFTS, read
from zh_story_recurrences import preview_ids
import json


def main():
    totals=Counter()
    programs={}
    by_program={}
    shards=[]
    for catalog in sorted(BASE.glob('sn*/block-*.catalog.json')):
        name=catalog.parent.name
        c=Counter()
        entries=read(catalog)['entries']
        ids={e['entry_id']:e for e in entries}
        legacy={e['entry_id'] for e in entries if 'grouping' in e or e['targets']['zh-Hans']['text']}
        bound=set(legacy)
        c['previous_records']=len(legacy)
        path=DRAFTS/name/catalog.name.replace('.catalog','')
        for g in (read(path)['entries'].values() if path.exists() else ()):
            c['new_groups']+=1
            preserved_layout = g.get('kind') == 'layout' and g['zh'] == g['ja'] and not g['ja'].strip()
            if (not g['zh'].strip() and not preserved_layout) or set(g['members']) & bound or not set(g['members'])<=ids.keys():
                raise ValueError(f"Conflicting or empty source binding {g['id']}")
            bound.update(g['members'])
            c['new_'+g.get('kind','story')+'_records']+=len(g['members'])
            if 'reused_from' in g:
                c['author_selected_reuse_groups' if g.get('reuse_method')=='author-selected' else 'context_reuse_groups']+=1
        by_program.setdefault(name,set()).update(bound)
        for e in entries:
            channel='primary' if e['record_kind']=='primary_text' else 'ruby'
            c[channel]+=1
            if e['entry_id'] in bound:
                c[channel+'_bound']+=1
        shards.append(dict(program=name,shard=catalog.name.split('.')[0],**c))
        programs.setdefault(name,Counter()).update(c)
        totals.update(c)
    choices={}
    for name,bound in by_program.items():
        index=[]
        preview_ids(name,index)
        choices[name]=dict(instructions=len({r['choice'] for r in index}),option_references=len(index),
            references_with_bound_text=sum(bool(r['source_ids']) and set(r['source_ids'])<=bound for r in index),
            references_with_dynamic_insertions=sum(bool(r['dynamic']) for r in index))
    report=dict(locale='zh-Hans',stage='first draft',release_allowed=False,
                scope='Three indexed scripts. Bound ruby is source association, not separately translated prose.',
                programs=programs,totals=totals,original_6c_choices=choices,shards=shards)
    path=DRAFTS/'progress.json'
    path.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(totals,ensure_ascii=False))


if __name__=='__main__':
    main()
