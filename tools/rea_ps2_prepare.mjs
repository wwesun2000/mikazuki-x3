import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { ADAPTER_ID, sha256File } from './rea_ps2_profile.mjs';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = join(project, 'local/dependencies/rea-ps2');
const sourceModules = process.argv[2] ?? process.env.REA_NODE_MODULES;
const sourcePackage = join(sourceModules, 'rea-agents');
const sourceMetadata = JSON.parse(readFileSync(join(sourcePackage, 'package.json'), 'utf8'));
if (sourceMetadata.version !== '6.8.0') throw new Error('Only the reviewed rea-agents 6.8.0 package is supported.');
const modules = join(root, 'node_modules');
const packageRoot = join(modules, 'rea-agents');
mkdirSync(root, { recursive: true });
const marker = join(root, 'patch-manifest.json');
if (existsSync(marker)) {
  const manifest = JSON.parse(readFileSync(marker, 'utf8'));
  if (sha256File(join(packageRoot, manifest.bundle)) !== manifest.patched_sha256) throw new Error('Existing local patched bundle differs from its manifest.');
  if (sha256File(join(sourcePackage, manifest.bundle)) !== manifest.original_sha256) throw new Error('The original reviewed package changed.');
}
if (existsSync(modules) && !existsSync(marker)) throw new Error('Unfinished local preparation exists; inspect it before reusing or removing it.');
if (!existsSync(modules)) cpSync(sourceModules, modules, { recursive: true, errorOnExist: true, force: false });
const candidates = readdirSync(join(packageRoot, 'dist/cli-runtime')).filter(n => /^binary-.*\.js$/.test(n));
const bundleName = candidates.find(n => readFileSync(join(packageRoot, 'dist/cli-runtime', n), 'utf8').includes('inspectWindowsP0TargetSupport ='));
if (!bundleName) throw new Error('Reviewed CLI binary bundle was not found.');
const bundle = `dist/cli-runtime/${bundleName}`;
const bundlePath = join(packageRoot, bundle);
let code = readFileSync(join(sourcePackage, bundle), 'utf8');
const originalSha = sha256File(join(sourcePackage, bundle));
const replacements = [];
function replaceOnce(label, from, to) {
  if (code.split(from).length !== 2) throw new Error(`Patch anchor is not unique: ${label}`);
  code = code.replace(from, to);
  replacements.push(label);
}
replaceOnce('exact-ELF processor admission',
  'ghidraProcessorUnsupportedReason = (target) => {',
  'ghidraProcessorUnsupportedReason = (target) => {\n\t\t\tif (isReaLocalPs2Target(target)) return null;');
replaceOnce('exact-ELF Windows admission',
  'inspectWindowsP0TargetSupport = (target, diagnostics) => {',
  'inspectWindowsP0TargetSupport = (target, diagnostics) => {\n\t\t\tif (isReaLocalPs2Target(target)) return { status: "supported", code: null, reason: null, diagnostics: { ...diagnostics, local_research_adapter: "'+ADAPTER_ID+'" } };');
replaceOnce('fixed EE language',
  'ghidraPinnedLanguage = (target) => ghidraMipsLanguageOverride(target)',
  'ghidraPinnedLanguage = (target) => reaPs2PinnedLanguage(target) ?? ghidraMipsLanguageOverride(target)');
replaceOnce('profile identity and extension commitment',
  '...pinnedLanguage\n\t\t\t};',
  '...pinnedLanguage,\n\t\t\t\t...reaPs2ExtraProfileParameters(target)\n\t\t\t};');
replaceOnce('pre-launch extension revalidation',
  'const psp = this.options.pspExtension;',
  'reaPs2ValidateContext();\n\t\t\t\t\tconst psp = this.options.pspExtension;');
replaceOnce('explicit local limitations',
  'const targetLimitations = [',
  'const targetLimitations = [\n\t\t\t\t...(isReaLocalPs2Target(target) ? PS2_LIMITATIONS : []),');
replaceOnce('replace upstream PE-only scope claim for the local target',
  'const providerLimitations = installation.platform === "win32" ? windowsP0Limitations :',
  'const providerLimitations = installation.platform === "win32" ? (isReaLocalPs2Target(target) ? windowsP0Limitations.filter(value => !value.startsWith("Windows Ghidra P0 accepts native")) : windowsP0Limitations) :');
replaceOnce('limit local headless analyzer to two CPUs',
  '"-readOnly",\n\t\t\t\t"-deleteProject",',
  '...(process.env.REA_LOCAL_PS2_CONTEXT ? ["-max-cpu", "2"] : []),\n\t\t\t\t"-readOnly",\n\t\t\t\t"-deleteProject",');
code = 'import { isReaLocalPs2Target, reaPs2PinnedLanguage, reaPs2ExtraProfileParameters, reaPs2ValidateContext, PS2_LIMITATIONS } from "./reaPs2LocalProfile.mjs";\n'+code;
const helperSource = join(project, 'tools/rea_ps2_profile.mjs');
cpSync(helperSource, join(packageRoot, 'dist/cli-runtime/reaPs2LocalProfile.mjs'));
writeFileSync(bundlePath, code);
const manifest = {
  adapter_id: ADAPTER_ID, upstream: 'rea-agents@6.8.0', source_package: sourcePackage,
  source_package_json_sha256: sha256File(join(sourcePackage, 'package.json')),
  bundle, original_sha256: originalSha, patched_sha256: sha256File(bundlePath),
  helper_sha256: sha256File(helperSource), replacements,
  references: ['https://github.com/morluto/rea/pull/5240', 'https://github.com/morluto/rea/pull/6422'],
  scope: 'CLI bundle only; MCP bundle, Windows ownership, generic MIPS checks and original ELF unchanged',
  created_at: new Date().toISOString()
};
manifest.patch_sha256 = createHash('sha256').update(JSON.stringify({ originalSha, patched: manifest.patched_sha256, helper: manifest.helper_sha256 })).digest('hex');
writeFileSync(marker, JSON.stringify(manifest, null, 2)+'\n');
console.log(JSON.stringify({ prepared: true, root, adapter_id: ADAPTER_ID, replacements }));
