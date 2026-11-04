import hashlib
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import choice_branch as choice
from opening_instructions import frame_one


def instruction(raw):
    return frame_one(raw,0,len(raw))


class OperandTests(unittest.TestCase):
    def test_choice_requires_all_declared_options(self):
        with self.assertRaises(ValueError):
            choice.decode_operands(instruction(bytes.fromhex('6c03010200')))

    def test_truncated_label_and_extra_tail_refused(self):
        for raw in ('6a020f78','6a040f780001'):
            with self.assertRaises(ValueError):
                choice.decode_operands(instruction(bytes.fromhex(raw)))

    def test_signed_big_endian_assignment(self):
        op=choice.decode_operands(instruction(bytes.fromhex('6805017a06ffff')))
        variables={}
        choice.assign_only(op,variables)
        self.assertEqual(variables,{378:-1})

    def test_unknown_operator_not_nop(self):
        op=choice.decode_operands(instruction(bytes.fromhex('6805017a050001')))
        with self.assertRaisesRegex(ValueError,'not a NOP'):
            choice.assign_only(op,{})

    def test_unknown_gate_value_not_false_default(self):
        op=choice.decode_operands(instruction(bytes.fromhex('7008017d0700010f7800')))
        with self.assertRaisesRegex(ValueError,'Unknown variable'):
            choice.conditional_jump_only(op,{})
        self.assertFalse(choice.conditional_jump_only(op,{381:1}))
        self.assertTrue(choice.conditional_jump_only(op,{381:0}))

    def test_unknown_opcode_rejected(self):
        with self.assertRaisesRegex(ValueError,'No recovered'):
            choice.decode_operands(instruction(b'\x01'))

    def test_wrong_script_rejected(self):
        with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):
            choice.Script(b'wrong build')


@unittest.skipUnless((ROOT/'local/assets/SCENARIO/sn4g.sn4').is_file(),'Local fixture absent')
class OriginalEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data=(ROOT/'local/assets/SCENARIO/sn4g.sn4').read_bytes()
        cls.elf=(ROOT/'local/extracted/SLPM_664.52').read_bytes()
        cls.report=choice.build_report(cls.data,cls.elf)
        cls.script=choice.Script(cls.data)

    def test_source_mutation_rejected(self):
        with self.assertRaises(ValueError):
            choice.Script(self.data[:-1]+bytes((self.data[-1]^1,)))

    def test_two_distinct_targets_and_assignments(self):
        ts=self.report['choice']['targets']
        self.assertEqual([(t['option']['block_selector'],t['option']['label']) for t in ts],
                         [(15,'pr01_0115'),(13,'pk01_0010')])
        self.assertEqual([t['assignment']['variable_id'] for t in ts],[378,378])
        self.assertEqual([t['assignment']['rhs'] for t in ts],[0,1])
        for t in ts:
            self.assertEqual([r['opcode'] for r in t['preview_instructions']],[0x22,0x6a,2,4,0x16])
            self.assertIn('original_0x111738_skip',t['preview_instructions'][1]['preview_action'])

    def test_preview_allowlist_distinguishes_jump_and_assign(self):
        a=self.report['context_contract']['preview_allowlist']
        self.assertEqual(len(a),19)
        self.assertIn(0x1b,a)
        self.assertIn(0x16,a)
        self.assertNotIn(0x6a,a)
        self.assertNotIn(0x68,a)

    def test_raw_evidence_matches_source(self):
        rows=[self.report['choice']['instruction']]
        for t in self.report['choice']['targets']:
            rows+=t['preview_instructions']+[t['assignment_instruction']]
        for r in rows:
            raw=self.data[r['offset']:r['end_exclusive']]
            self.assertEqual(raw.hex(),r['raw_hex'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(),r['raw_sha256'])
        for w in self.report['elf_evidence']:
            for r in w['instructions']:
                self.assertEqual(self.elf[r['file_offset']:r['file_offset']+4].hex(),r['raw_hex'])

    def test_unresolved_label_and_runtime_selector_rejected(self):
        for selector,label in [(15,'absent'),(32,'pr01_0115')]:
            with self.assertRaises(ValueError):
                self.script.resolve(selector,label)

    def test_runtime_templates_length_and_final_bridge(self):
        templates=self.report['context_contract']['runtime_templates']
        self.assertEqual([t['runtime_block_selector'] for t in templates],[32,33])
        for t in templates:
            self.assertEqual(t['byte_length'],22)
            self.assertTrue(t['raw_hex'].endswith('1b'))


if __name__=='__main__':
    unittest.main()
