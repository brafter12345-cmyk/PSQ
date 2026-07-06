/**
 * gen_rating_data.mjs — generate src/rating-data.js (ESM) from the legacy
 * vanilla data layer `SME Rating Engine/sme-data.js`, WITHOUT hand-transcription.
 *
 * The legacy file is a classic <script> (top-level `const`/`function` in the
 * global scope). We produce an ESM module by prefixing each top-level
 * declaration with `export ` — nothing else is changed, so the values are
 * byte-for-byte identical. `tools/parity.mjs` then proves the generated
 * exports deep-equal the values the legacy file evaluates to.
 *
 * Re-run this whenever the legacy sme-data.js changes (before Render retirement,
 * the legacy file remains the single source of truth for the rating DATA).
 *
 *   node tools/gen_rating_data.mjs
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..', '..'); // sme_rating_engine/frontend/tools -> repo root
const SRC = resolve(REPO_ROOT, 'SME Rating Engine', 'sme-data.js');
const OUT = resolve(__dirname, '..', 'src', 'rating-data.js');

const legacy = readFileSync(SRC, 'utf8');

// Prefix `export ` on every TOP-LEVEL declaration (column 0). Continuation
// lines of multi-line arrays/objects are indented or are closing brackets, so
// they never match — only the declaration head does.
const DECL = /^(const|let|var|function)\s/;
const transformed = legacy
  .split('\n')
  .map((line) => (DECL.test(line) ? 'export ' + line : line))
  .join('\n');

const banner = `/**
 * rating-data.js — GENERATED, DO NOT EDIT BY HAND.
 * Source of truth: ../../../SME Rating Engine/sme-data.js  (legacy vanilla app).
 * Regenerate:      node tools/gen_rating_data.mjs
 * Parity-locked:   node tools/parity.mjs  (deep-equals every export vs the legacy values).
 */
`;

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, banner + transformed, 'utf8');

const nExports = transformed.split('\n').filter((l) => l.startsWith('export ')).length;
console.log(`wrote ${OUT}`);
console.log(`  from ${SRC}`);
console.log(`  ${nExports} top-level exports`);
