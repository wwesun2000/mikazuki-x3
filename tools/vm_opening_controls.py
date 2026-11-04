"""Bound opening fade/centering and effect-surface static evidence."""
import hashlib
import json
import struct
from vm_handlers import Image,ROOT
from vm_presentation_semantics import extended_decode
from opening_instructions import SCRIPT_SHA


def copy_packet(draw_frame_register,destination=8000):
    """175FA0/176970/175FC0 arithmetic, ordinary640x224 path.

    Values are GS packet words. This is not a renderer or a claim of which
    gameplay objects were already drawn into the selected surface.
    """
    source=2240 if draw_frame_register&0x1ff else 0
    return dict(source_base=source,destination_base=destination,width=640,height=224,
        registers={'0x50':source|(10<<16)|(destination<<32)|(10<<48),
                   '0x51':0,'0x52':640|(224<<32),'0x53':2,'0x3f':0})


REGIONS=[(0x12BA68,0x12BB58),(0x113898,0x113AE0),(0x16B750,0x16B780),
 (0x133930,0x133CE8),(0x16B910,0x16B980),(0x16A8C8,0x16A910),
 (0x1682F8,0x168318),(0x175FA0,0x176108),(0x176970,0x1769E0),
 (0x179DE0,0x179EB8),(0x18E840,0x18E8C4),(0x18EA98,0x18EC50),
 (0x101398,0x101420),(0x1799A8,0x179B58),(0x1505F0,0x1506F8),
 (0x13BF98,0x13C018),(0x13CD20,0x13D098),(0x13D2A0,0x13D388),
 (0x176638,0x176888),(0x135528,0x135580),(0x18EC68,0x18ED90),
 (0x1284F8,0x128558),(0x16A680,0x16A698),(0x168380,0x168390)]


def build_report():
    image=Image((ROOT/'local/extracted/SLPM_664.52').read_bytes())
    data=(ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
    if hashlib.sha256(data).hexdigest()!=SCRIPT_SHA:raise ValueError('Unbound script')
    if data[661564:661570]!=bytes.fromhex('5a0000003c3c'):raise ValueError('Unexpected opening sequence')
    regions=[]
    for start,end in REGIONS:
        r=image.region(start,end)
        for i in r['instructions']:i['extended_decode']=extended_decode(int(i['raw_word'],16),int(i['address'],16))
        regions.append(r)
    return dict(evidence_id='VM-OPENING-CONTROLS-001',authority='local static analysis; no original frame trace',
        source={'elf_sha256':image.sha256,'script_sha256':SCRIPT_SHA},
        source_slice={'offset':661564,'raw_hex':data[661564:661574].hex()},
        semantics={'5a':'signedBE32 n; save current glyph counts in2F0+C/+10; storef32(128/f32(n)) in+14; defaults current/step both0/0',
            '55':'signedBE32 ->primarybase+18 line_spacing only; no preference write, no wait orbranch;1284F8->16A680->168380',
            '59':'signedBE32 n; save counts in2F0+0/+4; storef32(-128/f32(n)) in+8; defaults128/0',
            '31':'apply saved+8 step to nodes from saved+0/+4 through currentcount-1; defaults unchanged',
            '32':'existing vm_text_controls applies saved+14 step to saved+C/+10 range; restoresdefaults128/128',
            '3c':'savecursor; available=right-currentx+1; scan02 fullrawpairedunits with21 skipped; dynamicnames0D..11 explicitdependency; stop04/0B/1A/1B/6A/6B/85; all otheropcode spans skipped by111738; subtractletterspacing each scan iteration; ifwidth<=available addtrunc((available-width)/2) tox andsyncRuby;restorecursor',
            '3c_first_sample':'sourceafter3C is04, width0, available577, x32->320; original04 still executes next'},
        constants=[dict(address=hex(a),raw_word=hex(image.word(a)),value=struct.unpack('<f',struct.pack('<I',image.word(a)))[0])
                   for a in range(0x235e50,0x235e60,4)],
        effect_surface=dict(
            correction='175FC0 is a command-packet builder, not a getter returning a surface',
            phase2='18EC2C->176970; source selected from drawcontext+0->+A0 low9bits; fixedtwo bases0/2240;dest8000',
            packet_examples=[copy_packet(0),copy_packet(1)],
            phase01='18EC3C->179DE0->13D040 returns RAM snapshot buffer;176638 emits upload path; field selection adds0x8C000',
            ram_snapshot={'allocation':'13BF98 allocates0x118000;13BFBC stores pointer gp-31196,secondhalf gp-31192=base+0x8C000',
                'capture':'13CD20->13CCA0->13CEC0 builds readback packet(register53=1) and destinationRAM transfer',
                'gates':'capture depends gp-31212 state andgp-31208 stage; cannot assume current liveimage'},
            draw_order=['1013B0..1013BC taskpass0','1013C4 snapshot-stage13D2A0','1013CC19D498',
                        '1013DC text16BCE8','1013E4..1013F0 taskpass1'],
            draw_gate='1799A8 accepts active task withdraw+18 andno+28hide; task+0C must equalpass or2',
            effect67_group='18E8BC->179C60(task,0), therefore pass0 before currentglyph drawing',
            effect65_group='6F65 uses18ED58->18EC68,then18ED70->179C60(task,0); a separate18ED20 wrapper sets1 and must not be conflated',
            modern_constraint='Capture/composite atmatching scene layer; do not substitute a background asset or automaticallyinclude currenttext',
            unresolved=['Exact previous snapshot acquisition frame andmode during originalopening needs dynamictrace',
                'Interlaced640x224 field composition to final640x448 andGPU pixel/raster rules not ported bythis evidence']),
        limitations=['Zero fade divisor blocks pending R5900 nonfinite behavior; hostfloat32 arithmetic is a reference',
            '3C dynamic name expansion blocks; scan-onlyskip is not executionNOP',
            'No claim of complete effect renderer or actualPS2image equivalence'],evidence_regions=regions)


def main():
    r=build_report()
    (ROOT/'analysis/vm_opening_controls.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'evidence_regions':len(r['evidence_regions']),'output':'analysis/vm_opening_controls.json'}))


if __name__=='__main__':main()
