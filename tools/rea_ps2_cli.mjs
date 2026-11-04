import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { ADAPTER_ID, TARGET_SHA256, sha256File, validateElf, fingerprintExtension } from './rea_ps2_profile.mjs';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = join(project, 'local/dependencies/rea-ps2');
const target = join(project, 'local/extracted/SLPM_664.52');
const ghidra = join(project, 'local/dependencies/ghidra-ee/ghidra_12.1.4_PUBLIC');
const java = process.env.JAVA_HOME;
const node = process.execPath;
const args = process.argv.slice(2);
const mode = args.shift() ?? '--preflight';
if (!['--preflight', 'inspect', 'function', 'decompile'].includes(mode)) throw new Error('Allowed commands: --preflight, inspect, function <address>, decompile <address>.');
const procedure = mode === 'function' || mode === 'decompile' ? args.shift() : undefined;
if ((procedure !== undefined && !/^0x[0-9a-f]+$/i.test(procedure)) || args.length || ((mode === 'function' || mode === 'decompile') && !procedure)) throw new Error('Select exactly one explicit hexadecimal function address.');
if (!existsSync(node)) throw new Error('The pinned Node 24.22.2 runtime is missing.');
const manifest = JSON.parse(readFileSync(join(root, 'patch-manifest.json'), 'utf8'));
const packageRoot = join(root, 'node_modules/rea-agents');
if (sha256File(join(packageRoot, manifest.bundle)) !== manifest.patched_sha256 ||
    sha256File(join(packageRoot, 'dist/cli-runtime/reaPs2LocalProfile.mjs')) !== manifest.helper_sha256 ||
    sha256File(join(project, 'tools/rea_ps2_profile.mjs')) !== manifest.helper_sha256) throw new Error('Patched files differ from the reviewed local manifest.');
const elf = validateElf(target);
const extension = fingerprintExtension(join(ghidra, 'Ghidra/Extensions/ghidra-emotionengine-reloaded'));
const context = { adapter_id: ADAPTER_ID, patch_sha256: manifest.patch_sha256, target_path: target, target_sha256: TARGET_SHA256, ghidra_root: ghidra, extension };
if (mode === '--preflight') {
  console.log(JSON.stringify({ ready: true, adapter_id: ADAPTER_ID, elf, extension_sha256: extension.sha256, ghidra, java, node, analysis_started: false }, null, 2));
  process.exit(0);
}
const run = join(root, 'runs', `${new Date().toISOString().replace(/[:.]/g, '-')}-${mode}`);
mkdirSync(run, { recursive: true });
const temp = join(root, 'private-temp');
mkdirSync(temp, { recursive: true });
const priorRuntimeDirectories = new Set(readdirSync(temp));
// Preserve only diagnostics, never the authenticated bridge/session descriptors.
function preserveProviderLogs() {
  for (const name of readdirSync(temp)) {
    if (priorRuntimeDirectories.has(name) || !name.startsWith('rea-ghidra-')) continue;
    for (const log of ['ghidra.log', 'script.log']) {
      const source = join(temp, name, log);
      try {
        const bytes = readFileSync(source);
        const destination = join(run, 'provider-logs', name);
        mkdirSync(destination, { recursive: true });
        writeFileSync(join(destination, log), bytes);
      } catch (error) { if (!['ENOENT', 'EBUSY', 'EACCES'].includes(error.code)) throw error; }
    }
  }
}
const env = { ...process.env };
for (const key of Object.keys(env)) if (key.startsWith('REA_') || key === 'GHIDRA_INSTALL_DIR' || key === 'JAVA_HOME' || key === 'JAVA_TOOL_OPTIONS' || key === 'JDK_JAVA_OPTIONS' || key === '_JAVA_OPTIONS') delete env[key];
Object.assign(env, { GHIDRA_INSTALL_DIR: ghidra, JAVA_HOME: java, TEMP: temp, TMP: temp,
  GHIDRA_HEADLESS_MAXMEM: '2G',
  REA_ANALYSIS_PROVIDER: 'ghidra', REA_GHIDRA_STARTUP_TIMEOUT_MS: '600000',
  REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS: '120', REA_LOCAL_PS2_CONTEXT: JSON.stringify(context) });
const cliArgs = [join(packageRoot, 'scripts/rea.mjs'), mode, target, ...(procedure ? [procedure] : []), '--provider', 'ghidra', '--json'];
writeFileSync(join(run, 'request.json'), JSON.stringify({ context, mode, procedure: procedure ?? null, node, java }, null, 2)+'\n');
process.stderr.write(`Local REA PS2 research run: ${run}\n`);
const child = spawn(node, cliArgs, { env, cwd: project, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
writeFileSync(join(run, 'process.json'), JSON.stringify({ child_pid: child.pid, executable: node, argv: cliArgs, started_at: new Date().toISOString() }, null, 2)+'\n');
const logTimer = setInterval(preserveProviderLogs, 1000);
let stdout = '', stderr = '';
child.stdout.on('data', chunk => { stdout += chunk; process.stdout.write(chunk); });
child.stderr.on('data', chunk => { stderr += chunk; process.stderr.write(chunk); });
child.on('error', error => { stderr += String(error); });
const code = await new Promise(resolveExit => child.on('close', resolveExit));
clearInterval(logTimer);
preserveProviderLogs();
writeFileSync(join(run, 'result.json'), stdout);
writeFileSync(join(run, 'stderr.log'), stderr);
const unchanged = sha256File(target) === TARGET_SHA256;
const extensionUnchanged = fingerprintExtension(extension.root).sha256 === extension.sha256;
writeFileSync(join(run, 'completion.json'), JSON.stringify({ exit_code: code, target_unchanged: unchanged, extension_unchanged: extensionUnchanged, child_pid: child.pid, completed_at: new Date().toISOString() }, null, 2)+'\n');
if (!unchanged || !extensionUnchanged) throw new Error('Target or extension identity changed during analysis.');
process.exitCode = code ?? 1;
