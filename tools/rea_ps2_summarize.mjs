import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256File } from './rea_ps2_profile.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../local/dependencies/rea-ps2/runs');
const run = resolve(process.argv[2] ?? '');
const rel = relative(root, run);
if (!rel || rel.startsWith('..') || rel.includes(':')) throw new Error('Select a completed run inside this adapter\'s runs directory.');
const resultPath = join(run, 'result.json');
const evidence = JSON.parse(readFileSync(resultPath, 'utf8'));
const completion = JSON.parse(readFileSync(join(run, 'completion.json'), 'utf8'));
if (completion.exit_code !== 0 || !evidence.evidence_id) throw new Error('A successful REA Evidence result is required.');
const dossier = evidence.normalized_result;
if (typeof dossier.pseudocode !== 'string' || !dossier.pseudocode.trim()) throw new Error('This run has no nonempty function pseudocode.');
writeFileSync(join(run, 'function.pseudo.c'), `/* Ghidra pseudocode, not original or buildable source.\n * Evidence: ${evidence.evidence_id}\n * Artifact SHA-256: ${evidence.subject.digest.sha256}\n */\n${dossier.pseudocode}\n`);
const summary = {
  evidence_id: evidence.evidence_id, result_sha256: sha256File(resultPath),
  provider: evidence.provider, local_adapter: evidence.analysis_profile.parameters.local_adapter,
  artifact_sha256: evidence.subject.digest.sha256,
  language: evidence.analysis_profile.parameters.language_id,
  compiler: evidence.analysis_profile.parameters.compiler_spec_id,
  abi_basis: evidence.analysis_profile.parameters.mips_abi_basis,
  procedure: dossier.procedure,
  pseudocode_characters: dossier.pseudocode.length,
  basic_blocks: dossier.basic_blocks?.length ?? null,
  callers: dossier.callers?.length ?? null, callees: dossier.callees?.length ?? null,
  limitations: evidence.limitations, completion
};
writeFileSync(join(run, 'summary.json'), JSON.stringify(summary, null, 2)+'\n');
console.log(JSON.stringify({ evidence_id: summary.evidence_id, address: dossier.procedure.address, pseudocode_characters: summary.pseudocode_characters, output: run }));
