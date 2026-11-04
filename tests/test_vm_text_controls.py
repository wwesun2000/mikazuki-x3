import copy
import hashlib
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import vm_text_controls as t


def font():
    return dict(primary=dict(x=100,y=80,size=24,style=0,letter_spacing=2,line_spacing=4,rgb=[100,110,120]),
        ruby=dict(x=100,y=68,size=12,style=0,vertical_offset=-1),origin_x=100,origin_y=80,right_limit=600,
        line_count=0,anchor_x=84,channels=[dict(plus08=0.0,plus0c=4.0,glyphs=[]),
            dict(plus08=0.0,plus0c=4.0,glyphs=[])])


class Metrics:
    def lookup(self,unit,style,size):return dict(width=30+style+size)


class TextControls(unittest.TestCase):
    def test_hash_bound(self):
        with self.assertRaises(ValueError):t.Image(b'not-elf')

    def test_setting_stub(self):
        for n in (1,2,5,18,30,-1):self.assertEqual(t.retail_setting(n),0)

    def test_init_cadence_preserves_pending(self):
        s=dict(manager=dict(plus294=9,plus298=1),font=font())
        r=t.initialize_control(s,0x41,1)['state']
        self.assertEqual(r['manager'],dict(plus294=0,plus298=1,plus31c=1,plus29c=1))

    def test_init_ruby_sign_and_deferred_alignment(self):
        s=dict(manager={},font=font());r=t.initialize_control(s,0x45,255)['state']
        self.assertEqual(r['manager']['plus328'],255)
        self.assertEqual(r['font']['ruby']['vertical_offset'],-1)
        self.assertEqual(r['font']['ruby']['y'],68)

    def test_init_origin_at_old_origin_repositions(self):
        s=dict(manager={},font=font());s['font']['line_count']=9
        r=t.initialize_control(s,0x5e,32)['state']
        self.assertEqual((r['font']['primary']['x'],r['font']['primary']['y']),(32,80))
        self.assertEqual(r['font']['line_count'],0);self.assertEqual(r['font']['anchor_x'],16)

    def test_init_origin_active_line_clamps_only_axis(self):
        s=dict(manager={},font=font());s['font']['primary'].update(x=180,y=200);s['font']['line_count']=3
        r=t.initialize_control(s,0x5e,190)['state']
        self.assertEqual((r['font']['primary']['x'],r['font']['primary']['y']),(190,200))
        self.assertEqual(r['font']['line_count'],3)
        r=t.initialize_control(s,0x62,32)['state']
        self.assertEqual(r['font']['primary']['y'],200);self.assertEqual(r['font']['ruby']['y'],68)

    def test_init_margins_and_spacing(self):
        s=dict(manager={},font=font())
        for op,v in [(0x60,32),(0x64,32),(0x54,0),(0x56,7)]:s=t.initialize_control(s,op,v)['state']
        self.assertEqual((s['font']['right_limit'],s['font']['bottom_limit']),(608,416))
        self.assertEqual((s['font']['primary']['letter_spacing'],s['font']['primary']['line_spacing']),(0,7))

    def test_init_be32_signed(self):
        r=t.parse(bytes.fromhex('54ffffffff'),0);self.assertEqual(r['value'],-1)
        self.assertEqual(r['raw_unsigned'],0xffffffff)

    def test_actual_header_init(self):
        data=(t.ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
        self.assertEqual([(t.parse(data,a)['opcode'],t.parse(data,a)['value']) for a in
            (0xad477,0xad47c,0xad481,0xad486,0xad48b,0xad490,0xad495,0xad497)],
            [(0x5e,32),(0x60,32),(0x62,32),(0x64,32),(0x54,0),(0x56,7),(0x45,6),(0x41,1)])

    def test_parse_65_signed_and_66_unsigned(self):
        self.assertEqual(t.parse(bytes.fromhex('65ffff8000'),0)['x'],-1)
        self.assertEqual(t.parse(bytes.fromhex('65ffff8000'),0)['y'],-32768)
        self.assertEqual(t.parse(bytes.fromhex('66ffff8000'),0)['x'],65535)

    def test_truncation(self):
        for raw in ('4c00','4d00','65ffff','66'):
            with self.assertRaises(ValueError):t.parse(bytes.fromhex(raw),0)

    def test_style_sentinel(self):
        f=font();self.assertEqual(t.style_size(f,255,255),f)
        out=t.style_size(f,2,0,32);self.assertEqual((out['primary']['style'],out['primary']['size']),(2,32))
        self.assertEqual(f['primary']['style'],0)

    def test_missing_default(self):
        with self.assertRaises(t.UnresolvedDependency):t.style_size(font(),0,0)

    def test_position_sync(self):
        f=t.position(font(),-20,7,True)
        self.assertEqual((f['primary']['x'],f['primary']['y']),(80,87))
        self.assertEqual((f['ruby']['x'],f['ruby']['y'],f['anchor_x']),(80,74,64))

    def test_decoration_geometry(self):
        f=font();result=t.decoration(f,70,'atlas0')
        self.assertEqual([n['xyxy'] for n in result['nodes']],[[100,90,103,98],[103,90,167,98],[167,90,170,98]])
        self.assertEqual(result['nodes'][2]['uvuv'],[.9765625,.375,1.,.4375])
        self.assertEqual(result['font']['primary']['x'],172)
        self.assertEqual(result['font']['primary']['y'],80)
        self.assertEqual(f['channels'][0]['glyphs'],[])

    def test_decoration_wrap_except_at_origin(self):
        f=font();f['right_limit']=130
        self.assertFalse(t.decoration(f,70,'a')['wrapped'])
        f['primary']['x']=110;r=t.decoration(f,70,'a')
        self.assertTrue(r['wrapped']);self.assertEqual(r['font']['line_count'],1)

    def test_decoration_inverted_narrow_original(self):
        r=t.decoration(font(),2,'a');self.assertGreater(r['nodes'][1]['xyxy'][0],r['nodes'][1]['xyxy'][2])

    def test_decoration_requires_atlas(self):
        with self.assertRaises(t.UnresolvedDependency):t.decoration(font(),70,None)

    def test_range_defaults_and_restricted_nodes(self):
        f=font()
        for c in f['channels']:c['glyphs']=[{'step':0,'current':64},{'step':0,'current':32}]
        out=t.range_transition(f,dict(plus0c=1,plus10=2,plus14=-4))
        self.assertEqual([g['step'] for g in out['channels'][0]['glyphs']],[0,-4])
        self.assertEqual([g['step'] for g in out['channels'][1]['glyphs']],[0,0])
        self.assertEqual(out['channels'][0]['plus0c'],128)
        self.assertEqual(out['channels'][0]['glyphs'][1]['current'],32)

    def test_range_invalid_blocks(self):
        with self.assertRaises(t.UnresolvedDependency):t.range_transition(font(),dict(plus0c=3,plus10=0,plus14=0))

    def test_09_width_replaced_and_cursor_restored(self):
        r=t.lookahead09(bytes.fromhex('46644d0064022182a003'),0,font(),Metrics())
        self.assertEqual(r['width'],54);self.assertEqual(r['cursor'],0)

    def test_09_style_restoration(self):
        r=t.lookahead09(bytes.fromhex('4c02300282a003'),0,font(),Metrics())
        self.assertEqual(r['width'],80)
        self.assertEqual((r['font']['primary']['style'],r['font']['primary']['size']),(0,24))

    def test_09_wrap_even_at_origin(self):
        f=font();f['right_limit']=120
        r=t.lookahead09(bytes.fromhex('02303003'),0,f,Metrics())
        self.assertTrue(r['wrapped']);self.assertEqual(r['font']['primary']['y'],108)

    def test_09_stopper_accumulation(self):
        r=t.lookahead09(bytes.fromhex('46074d004604'),0,font(),Metrics())
        self.assertEqual(r['width'],77)

    def test_09_dynamic_dependency_and_replacement(self):
        with self.assertRaises(t.UnresolvedDependency):t.lookahead09(b'\x0d',0,font(),Metrics())
        seen=[]
        r=t.lookahead09(bytes.fromhex('46640f'),0,font(),Metrics(),dynamic_width=lambda m,d,p,f:seen.append(m) or 12)
        self.assertEqual(seen,[4]);self.assertEqual(r['width'],12)

    def test_09_dispatch_dependency(self):
        with self.assertRaises(t.UnresolvedDependency):t.lookahead09(bytes.fromhex('420104'),0,font(),Metrics())

    def test_09_safety_bound_and_truncation(self):
        with self.assertRaises(t.UnresolvedDependency):t.lookahead09(b'\0'*5,0,font(),Metrics(),max_steps=3)
        with self.assertRaises(ValueError):t.lookahead09(b'\2\x21',0,font(),Metrics())

    def test_09_begin_active_object(self):
        s=dict(font=font(),manager=dict(plus808=0),objects=dict(object2c_plus00=1),context_vtable=0x2239f0)
        r=t.begin09(s,font(),None);self.assertEqual(r['handler_return'],0)
        self.assertEqual(r['state']['context_vtable'],0x2239f0)

    def test_09_begin_context_timer(self):
        s=dict(font=font(),manager=dict(plus808=1,plus80c=9,plus814=0),objects=dict(object2c_plus00=0))
        seen=[];r=t.begin09(s,font(),lambda out:seen.append(out['context_vtable']))
        self.assertEqual(seen,[0x2239b0]);self.assertEqual(r['state']['manager']['plus814'],9)
        self.assertNotIn('context_vtable',s)

    def test_09_completion_still_yields(self):
        s=dict(object24_plus00=0,manager_plus808=0,context_vtable=0x2239b0)
        r=t.tick09(s,0x2100,lambda out:out.update(indicator=False))
        self.assertTrue(r['accepted']);self.assertEqual(r['context_return'],1)
        self.assertEqual(r['state']['context_vtable'],0x2239f0)
        self.assertEqual(s['context_vtable'],0x2239b0)

    def test_09_rejected_no_completion(self):
        s=dict(object24_plus00=0,manager_plus808=0,context_vtable=0x2239b0)
        r=t.tick09(s,0,None);self.assertFalse(r['accepted'])

    def _paragraph_state(self):
        return dict(manager=dict(plus2c0=1,plus808=1,plus810=55,plus814=0),
          objects=dict(object20_plus04=0,object20_flag5=False,object30_plus00=0,object2c_plus00=0),
          context_vtable=0x2239f0,events=[])

    def test_0c_keeps_context_and_record_order(self):
        s=self._paragraph_state()
        r=t.paragraph0c(s,mark_current=lambda o:o['events'].append('mark'),
          record_visit=lambda o:o['events'].append(('visit',o['manager']['plus814'])))
        self.assertEqual(r['state']['events'],['mark',('visit',55)])
        self.assertEqual(r['state']['context_vtable'],0x2239f0);self.assertEqual(r['handler_return'],1)
        self.assertEqual(s['events'],[])

    def test_0c_requires_history(self):
        with self.assertRaises(t.UnresolvedDependency):t.paragraph0c(self._paragraph_state())

    def test_0c_special_object_gate(self):
        s=self._paragraph_state();s['objects'].update(object20_plus04=1,object20_flag5=True)
        r=t.paragraph0c(s,mark_current=lambda o:None)
        self.assertEqual(r['handler_return'],0);self.assertEqual(r['state']['manager']['plus814'],0)

    def test_1a_temporarily_suppresses168(self):
        s=dict(script_runtime=dict(plus168=3,plus16c=9),manager=dict(plus32c_active=True),events=[])
        def transfer(o,label,flag):o['events'].append((label,flag,o['script_runtime']['plus168']))
        r=t.end1a(s,'top00_0000',close_menu=lambda o:o['events'].append('close'),
            end_recording=lambda o,n:o['events'].append(('end',n)),transfer=transfer)
        self.assertEqual(r['state']['events'],['close',('end',0),('top00_0000',1,0)])
        self.assertEqual(r['state']['script_runtime'],dict(plus168=3,plus16c=0))
        self.assertEqual(s['script_runtime']['plus16c'],9)

    def test_1a_unimplemented_menu_blocks(self):
        with self.assertRaises(t.UnresolvedDependency):t.end1a({},'label')

    def test_23_proven_stub_yields(self):
        s={'x':[1]};r=t.stub23(s);self.assertEqual(r['handler_return'],1)
        r['state']['x'].append(2);self.assertEqual(s,{'x':[1]})

    def test_actual_source_samples(self):
        data=(t.ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(),t.SCRIPT_SHA)
        self.assertEqual(t.parse(data,0xA1A52)['size'],48)
        self.assertEqual(t.parse(data,0xA1A5A)['width'],70)
        self.assertEqual(t.parse(data,0xA1F2E)['y'],7)


if __name__=='__main__':unittest.main()
