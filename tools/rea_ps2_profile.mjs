// Local, single-artifact research profile. This is not an upstream REA capability.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, realpathSync, lstatSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';

export const ADAPTER_ID = 'kamaitachi-slpm66452-r5900-win32-research-v1';
export const TARGET_SHA256 = '50ba47014cf2def901d2cd0f2319459525631a6b27bc8a030ccb9a98b4f57160';
export const LANGUAGE = { languageId: 'r5900:LE:32:default', compilerSpecId: 'default' };
export const PS2_LIMITATIONS = [
  'Unofficial local REA 6.8.0 Windows research adapter, restricted to the recorded SLPM_664.52 SHA-256; this is not upstream PS2 support.',
  'The ELF header leaves the ABI unspecified. The empty .mdebug.eabi64 section is not proof of EABI64; compiler storage and 128-bit EE register semantics require independent verification.',
  'Pseudocode is produced by Ghidra and ghidra-emotionengine-reloaded. It is not recovered original source or an execution oracle.',
  'Dynamic overlays, the five embedded .DVP.overlay payloads, VU microprograms, IOP/IRX, hardware state and full runtime behavior are outside this profile.',
  'RAM mirrors can duplicate strings and references; indirect calls, pointer-only handlers, vtables and unidentified functions may remain incomplete.'
];

export function sha256File(path) {
  if (lstatSync(path).isSymbolicLink() || !statSync(path).isFile()) throw new Error('A regular local file is required.');
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

export function validateElf(path) {
  const bytes = readFileSync(path);
  if (bytes.length < 52 || bytes.subarray(0, 4).toString('hex') !== '7f454c46' ||
      bytes[4] !== 1 || bytes[5] !== 1 || bytes[6] !== 1 ||
      bytes.readUInt16LE(16) !== 2 || bytes.readUInt16LE(18) !== 8 ||
      bytes.readUInt32LE(36) !== 0x20920001 || sha256File(path) !== TARGET_SHA256) {
    throw new Error('This research adapter admits only the exact recorded SLPM_664.52 ELF32 LE R5900 executable.');
  }
  return { sha256: TARGET_SHA256, bytes: bytes.length, flags: '0x20920001', abi: 'header-unspecified' };
}

export function fingerprintExtension(root) {
  const actual = realpathSync(root);
  const entries = [];
  let total = 0;
  function walk(directory) {
    for (const item of readdirSync(directory, { withFileTypes: true })) {
      const full = join(directory, item.name);
      if (item.isSymbolicLink()) throw new Error('Extension symlinks are outside the local profile.');
      if (item.isDirectory()) walk(full);
      else if (item.isFile()) {
        const size = statSync(full).size;
        total += size;
        if (total > 256 * 1024 * 1024 || entries.length > 4096) throw new Error('Extension exceeds the bounded fingerprint inventory.');
        entries.push({ path: relative(actual, full).split(sep).join('/'), bytes: size, sha256: sha256File(full) });
      } else throw new Error('Extension has an unsupported filesystem entry.');
    }
  }
  walk(actual);
  entries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const slaPath = join(actual, 'data/languages/r5900.sla');
  const sla = readFileSync(slaPath);
  if (sla.subarray(0, 3).toString('ascii') !== 'sla' || sla[3] !== 4) throw new Error('A precompiled format-4 r5900.sla is required; run the separate Ghidra preparation first.');
  const sourceFiles = entries.filter(e => /\.(slaspec|sinc)$/.test(e.path));
  if (sourceFiles.some(e => statSync(join(actual, e.path)).mtimeMs > statSync(slaPath).mtimeMs)) throw new Error('r5900.sla is older than its SLEIGH sources.');
  const props = readFileSync(join(actual, 'extension.properties'), 'utf8');
  if (!/^version=12\.1\.4\s*$/m.test(props)) throw new Error('This local profile requires the Ghidra 12.1.4 extension build.');
  return { root: actual, ghidra_version: '12.1.4', sha256: createHash('sha256').update(JSON.stringify(entries)).digest('hex'), files: entries };
}

export function matchesReaPs2Shape(target) {
  return target?.kind === 'executable' && target.format === 'elf' && target.architecture === 'mips' &&
    target.mips?.elfClass === 32 && target.mips.byteOrder === 'little' && target.mips.type === 2 &&
    target.mips.flags === 0x20920001 && target.mips.abiFlags === null && target.mips.gnuAttributes === null &&
    (target.mips.limitations?.length ?? 0) === 0;
}

function context() {
  const raw = process.env.REA_LOCAL_PS2_CONTEXT;
  if (!raw) return null;
  const value = JSON.parse(raw);
  if (value.adapter_id !== ADAPTER_ID || value.target_sha256 !== TARGET_SHA256 ||
      process.platform !== 'win32' || process.arch !== 'x64') throw new Error('Invalid local PS2 context.');
  return value;
}

export function reaPs2ValidateContext() {
  const c = context();
  if (!c) return null;
  validateElf(c.target_path);
  const expectedRoot = realpathSync(join(c.ghidra_root, 'Ghidra/Extensions/ghidra-emotionengine-reloaded'));
  if (expectedRoot !== realpathSync(c.extension.root)) throw new Error('Extension is outside the selected Ghidra installation.');
  const now = fingerprintExtension(expectedRoot);
  if (now.sha256 !== c.extension.sha256) throw new Error('The EE extension changed after preflight.');
  return c;
}

export function isReaLocalPs2Target(target) {
  if (!matchesReaPs2Shape(target)) return false;
  const c = context();
  if (!c || realpathSync(target.path) !== realpathSync(c.target_path)) return false;
  validateElf(target.path);
  return true;
}

export function reaPs2PinnedLanguage(target) {
  return isReaLocalPs2Target(target) ? LANGUAGE : undefined;
}

export function reaPs2ExtraProfileParameters(target) {
  if (!isReaLocalPs2Target(target)) return {};
  const c = reaPs2ValidateContext();
  return {
    mips_support_lane: ADAPTER_ID,
    mips_abi_basis: 'header-unspecified-no-eabi64-inference',
    local_adapter: { id: ADAPTER_ID, upstream: 'rea-agents@6.8.0', status: 'local-research-not-upstream', patch_sha256: c.patch_sha256 },
    ps2_extension: c.extension,
    ps2_scope: 'single-sha256-static-ee-image-no-vu-overlay-runtime',
    language_id: LANGUAGE.languageId, compiler_spec_id: LANGUAGE.compilerSpecId,
    language_selection: 'provider-pinned-v1'
  };
}
