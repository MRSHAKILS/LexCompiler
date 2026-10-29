import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Rebuilds server/analyzer/grammars/tree-sitter-sql.wasm from the C sources of
 * @derekstride/tree-sitter-sql with clang (wasm32) and wasm-ld, as a position-independent
 * side module loadable by @vscode/tree-sitter-wasm. The libc functions the grammar calls
 * (malloc, strncpy, iswspace, …) are imported from the runtime's main module, so only
 * declarations are needed here.
 */
const GRAMMAR = '@derekstride/tree-sitter-sql@0.3.11';
const OUT = path.join(process.cwd(), 'server/analyzer/grammars/tree-sitter-sql.wasm');

const headers: Record<string, string> = {
  'stdlib.h': '#pragma once\n#include <stddef.h>\nvoid *malloc(size_t); void *calloc(size_t, size_t); void *realloc(void *, size_t); void free(void *); void abort(void);\n',
  'string.h':
    '#pragma once\n#include <stddef.h>\nvoid *memcpy(void *, const void *, size_t); void *memmove(void *, const void *, size_t); void *memset(void *, int, size_t);\nint memcmp(const void *, const void *, size_t); size_t strlen(const char *); int strcmp(const char *, const char *); int strncmp(const char *, const char *, size_t); char *strncpy(char *, const char *, size_t);\n',
  'wctype.h': '#pragma once\ntypedef unsigned int wint_t;\nint iswspace(wint_t); int iswalnum(wint_t); int iswalpha(wint_t); int iswdigit(wint_t); wint_t towlower(wint_t); wint_t towupper(wint_t);\n',
  'assert.h': '#pragma once\n#define assert(x) ((void)0)\n',
  'stdio.h': '#pragma once\n#include <stddef.h>\ntypedef struct FILE FILE;\nint fprintf(FILE *, const char *, ...);\nint snprintf(char *, size_t, const char *, ...);\nextern FILE *stderr;\n',
};

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'lexcompiler-sql-grammar-'));
try {
  // --ignore-scripts: only the published sources are used; nothing from the package runs.
  const tarball = execFileSync('npm', ['pack', GRAMMAR, '--ignore-scripts', '--silent', '--pack-destination', work], { encoding: 'utf8', shell: process.platform === 'win32' }).trim();
  execFileSync('tar', ['xzf', path.join(work, tarball), '-C', work]);
  const inc = path.join(work, 'inc');
  fs.mkdirSync(inc);
  for (const [name, text] of Object.entries(headers)) fs.writeFileSync(path.join(inc, name), text);
  const src = path.join(work, 'package/src');
  const resource = execFileSync('clang', ['-print-resource-dir'], { encoding: 'utf8' }).trim();
  const flags = ['--target=wasm32', '-O2', '-fPIC', '-fvisibility=hidden', '-ffreestanding', '-nostdlibinc', '-isystem', inc, '-isystem', path.join(resource, 'include'), '-I', src];
  for (const f of ['parser', 'scanner']) execFileSync('clang', [...flags, '-c', path.join(src, `${f}.c`), '-o', path.join(work, `${f}.o`)], { stdio: 'inherit' });
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  execFileSync('wasm-ld', ['--experimental-pic', '-shared', '--no-entry', '--export=tree_sitter_sql', '--allow-undefined', '-O2', path.join(work, 'parser.o'), path.join(work, 'scanner.o'), '-o', OUT], { stdio: 'inherit' });
  console.log(`Built ${path.relative(process.cwd(), OUT)} from ${GRAMMAR} (sha256 ${crypto.createHash('sha256').update(fs.readFileSync(OUT)).digest('hex')})`);
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}
