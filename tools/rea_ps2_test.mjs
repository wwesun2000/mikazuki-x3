import assert from 'node:assert/strict';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ADAPTER_ID, matchesReaPs2Shape, validateElf, isReaLocalPs2Target } from './rea_ps2_profile.mjs';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const path = join(project, 'local/extracted/SLPM_664.52');
const target = { kind: 'executable', format: 'elf', architecture: 'mips', path,
  mips: { elfClass: 32, byteOrder: 'little', type: 2, flags: 0x20920001, abiFlags: null, gnuAttributes: null, limitations: [] } };
assert.equal(validateElf(path).abi, 'header-unspecified');
assert.equal(matchesReaPs2Shape(target), true);
const mutations = [
  t => t.format = 'pe', t => t.architecture = 'arm', t => t.mips.elfClass = 64,
  t => t.mips.byteOrder = 'big', t => t.mips.type = 1,
  t => t.mips.flags = 0x20924001, t => t.mips.flags = 0x10a23001,
  t => t.mips.abiFlags = undefined, t => t.mips.abiFlags = {},
  t => t.mips.gnuAttributes = undefined, t => t.mips.gnuAttributes = {},
  t => t.mips.limitations = ['incomplete']
];
for (const mutate of mutations) { const t = structuredClone(target); mutate(t); assert.equal(matchesReaPs2Shape(t), false); }
delete process.env.REA_LOCAL_PS2_CONTEXT;
assert.equal(isReaLocalPs2Target(target), false, 'Exact header alone must not enable the adapter.');
process.env.REA_LOCAL_PS2_CONTEXT = JSON.stringify({ adapter_id: ADAPTER_ID, target_sha256: '0'.repeat(64) });
assert.throws(() => isReaLocalPs2Target(target), /Invalid local PS2 context/);
delete process.env.REA_LOCAL_PS2_CONTEXT;
console.log(JSON.stringify({ passed: true, negative_cases: mutations.length + 2, target_bytes_unchanged: true }));
