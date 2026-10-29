import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { LegalClause } from '../../shared/types.js';

export type ProjectRole = 'viewer' | 'editor' | 'owner';
const RANK: Record<ProjectRole, number> = { viewer: 1, editor: 2, owner: 3 };

export interface Project {
  id: string;
  name: string;
  /** Repository root, inside the projects root (LEXCOMPILER_PROJECT_REPOS_ROOT). */
  repoPath: string;
  createdAt: string;
  createdBy: string;
  members: Array<{ sub: string; role: ProjectRole }>;
}

export interface ScanRecord {
  scanId: string;
  at: string;
  by: string;
  filesScanned: number;
  clauses: Array<{ clauseId: string; citation: string; status: string; violations: number }>;
}

export const roleAtLeast = (role: ProjectRole | null, min: ProjectRole) => !!role && RANK[role] >= RANK[min];

/** Projects, members, per-project clauses and scan ledgers, persisted as JSON under the data directory. */
export class ProjectStore {
  readonly reposRoot: string;
  private readonly dir: string;

  constructor(dataDir: string, reposRoot: string) {
    this.dir = path.join(dataDir, 'projects');
    this.reposRoot = path.resolve(reposRoot);
    fs.mkdirSync(this.dir, { recursive: true });
  }

  private get indexFile() {
    return path.join(this.dir, 'projects.json');
  }

  private write(file: string, data: unknown) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    fs.renameSync(tmp, file);
  }

  list(): Project[] {
    try {
      return JSON.parse(fs.readFileSync(this.indexFile, 'utf8')) as Project[];
    } catch {
      return [];
    }
  }

  get(id: string): Project | undefined {
    return this.list().find((p) => p.id === id);
  }

  /** Resolves a repository path, refusing anything outside the projects root. */
  resolveRepoPath(repoPath: string): string {
    const abs = path.resolve(this.reposRoot, repoPath);
    const rel = path.relative(this.reposRoot, abs);
    if (rel.startsWith('..') || path.isAbsolute(rel)) throw new Error(`Repository must be inside ${this.reposRoot}`);
    if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) throw new Error(`Repository ${repoPath} does not exist`);
    return abs;
  }

  create(input: { name: string; repoPath: string; owner: string; id?: string; trustedRepoPath?: boolean }): Project {
    const name = input.name.trim().slice(0, 120);
    if (!name) throw new Error('name is required');
    const repoPath = input.trustedRepoPath ? path.resolve(input.repoPath) : this.resolveRepoPath(input.repoPath);
    const projects = this.list();
    const id = input.id || `${name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'project'}-${crypto.randomBytes(3).toString('hex')}`;
    if (projects.some((p) => p.id === id)) throw new Error(`project ${id} already exists`);
    const project: Project = { id, name, repoPath, createdAt: new Date().toISOString(), createdBy: input.owner, members: [{ sub: input.owner, role: 'owner' }] };
    this.write(this.indexFile, [...projects, project]);
    return project;
  }

  update(id: string, fn: (p: Project) => void): Project {
    const projects = this.list();
    const p = projects.find((x) => x.id === id);
    if (!p) throw new Error(`project ${id} not found`);
    fn(p);
    if (!p.members.some((m) => m.role === 'owner')) throw new Error('a project needs at least one owner');
    this.write(this.indexFile, projects);
    return p;
  }

  delete(id: string): void {
    this.write(this.indexFile, this.list().filter((p) => p.id !== id));
    fs.rmSync(path.join(this.dir, id), { recursive: true, force: true });
  }

  roleOf(p: Project, sub: string): ProjectRole | null {
    return p.members.find((m) => m.sub === sub)?.role ?? null;
  }

  clauses(id: string): LegalClause[] | null {
    try {
      return JSON.parse(fs.readFileSync(path.join(this.dir, id, 'clauses.json'), 'utf8')) as LegalClause[];
    } catch {
      return null;
    }
  }

  saveClauses(id: string, clauses: LegalClause[]): void {
    this.write(path.join(this.dir, id, 'clauses.json'), clauses);
  }

  appendScan(id: string, record: ScanRecord): void {
    const file = path.join(this.dir, id, 'scans.jsonl');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, `${JSON.stringify(record)}\n`);
  }

  scans(id: string, limit = 50): ScanRecord[] {
    try {
      const lines = fs.readFileSync(path.join(this.dir, id, 'scans.jsonl'), 'utf8').trim().split('\n').filter(Boolean);
      return lines.slice(-limit).map((l) => JSON.parse(l) as ScanRecord).reverse();
    } catch {
      return [];
    }
  }
}
