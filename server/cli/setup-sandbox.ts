import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { resolvePython } from '../util/python.js';

/** Creates `.venv` and installs the real sandbox frameworks from requirements-sandbox.txt. */
const python = resolvePython();
if (!python) {
  console.error('No Python >= 3.10 interpreter found (set LEXCOMPILER_PYTHON).');
  process.exit(1);
}
const venv = path.join(process.cwd(), '.venv');
const venvPython = path.join(venv, process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
if (!fs.existsSync(venvPython)) {
  console.log(`Creating .venv with ${python.version}…`);
  execFileSync(python.command, [...python.prefixArgs, '-m', 'venv', venv], { stdio: 'inherit' });
}
execFileSync(venvPython, ['-m', 'pip', 'install', '--disable-pip-version-check', '-q', '-r', 'requirements-sandbox.txt'], { stdio: 'inherit' });
console.log('Sandbox frameworks installed in .venv (FastAPI, Pydantic, httpx, fakeredis, redis).');
