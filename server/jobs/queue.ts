import crypto from 'node:crypto';
import { nowIso, type Db } from '../db/index.js';

export interface JobContext {
  jobId: string;
  /** 1 on the first run. */
  attempt: number;
  maxAttempts: number;
}
export type JobHandler = (payload: Record<string, unknown>, ctx: JobContext) => Promise<void>;

export interface JobQueueOptions {
  maxAttempts?: number;
  pollMs?: number;
  /** Delay before retrying after attempt `n` failed. */
  backoffMs?: (attempt: number) => number;
  onError?: (err: unknown, job: { id: string; kind: string; attempt: number }) => void;
}

/**
 * Jobs kept in the database, so queued work survives a restart. One worker runs one job at a
 * time: z3-solver solves one formula at a time anyway, and scans stay in arrival order.
 */
export class JobQueue {
  private timer: NodeJS.Timeout | null = null;
  private running: Promise<unknown> | null = null;
  private readonly maxAttempts: number;
  private readonly pollMs: number;
  private readonly backoffMs: (attempt: number) => number;

  constructor(
    private readonly db: Db,
    private readonly handlers: Record<string, JobHandler>,
    private readonly options: JobQueueOptions = {}
  ) {
    this.maxAttempts = options.maxAttempts ?? 3;
    this.pollMs = options.pollMs ?? 1000;
    this.backoffMs = options.backoffMs ?? ((attempt) => 15_000 * 4 ** (attempt - 1));
  }

  /** Queues a job. Returns its id, or null when a job with the same dedupe key is already queued or running. */
  enqueue(kind: string, payload: Record<string, unknown>, options: { dedupeKey?: string; runAfter?: Date } = {}): string | null {
    if (!this.handlers[kind]) throw new Error(`no handler for job kind "${kind}"`);
    const id = crypto.randomUUID();
    const now = nowIso();
    const result = this.db
      .prepare(
        `INSERT OR IGNORE INTO jobs (id, kind, payload_json, dedupe_key, status, attempts, run_after, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'queued', 0, ?, ?, ?)`
      )
      .run(id, kind, JSON.stringify(payload), options.dedupeKey ?? null, (options.runAfter ?? new Date()).toISOString(), now, now);
    if (Number(result.changes) === 0) return null;
    this.kick();
    return id;
  }

  /** Starts the worker. Jobs a crash left running go back to the queue. */
  start(): void {
    if (this.timer) return;
    this.db.prepare("UPDATE jobs SET status = 'queued', updated_at = ? WHERE status = 'running'").run(nowIso());
    this.timer = setInterval(() => this.kick(), this.pollMs);
    this.timer.unref();
    this.kick();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private kick(): void {
    if (!this.timer || this.running) return;
    this.running = this.drain().finally(() => {
      this.running = null;
    });
  }

  /** Runs ready jobs until none is left. Returns how many ran. */
  async drain(): Promise<number> {
    let ran = 0;
    while (await this.runOnce()) ran++;
    return ran;
  }

  /** Claims and runs the next ready job. Returns false when none is ready. */
  async runOnce(): Promise<boolean> {
    const now = nowIso();
    const job = this.db
      .prepare(
        `UPDATE jobs SET status = 'running', attempts = attempts + 1, updated_at = ?
         WHERE id = (SELECT id FROM jobs WHERE status = 'queued' AND run_after <= ? ORDER BY run_after, created_at LIMIT 1)
         RETURNING id, kind, payload_json, attempts`
      )
      .get(now, now) as { id: string; kind: string; payload_json: string; attempts: number } | undefined;
    if (!job) return false;
    const attempt = Number(job.attempts);
    try {
      await this.handlers[job.kind](JSON.parse(job.payload_json) as Record<string, unknown>, { jobId: job.id, attempt, maxAttempts: this.maxAttempts });
      this.db.prepare("UPDATE jobs SET status = 'done', last_error = NULL, updated_at = ? WHERE id = ?").run(nowIso(), job.id);
    } catch (err) {
      const final = attempt >= this.maxAttempts;
      this.db
        .prepare('UPDATE jobs SET status = ?, last_error = ?, run_after = ?, updated_at = ? WHERE id = ?')
        .run(
          final ? 'failed' : 'queued',
          (err instanceof Error ? err.message : String(err)).slice(0, 2000),
          new Date(Date.now() + this.backoffMs(attempt)).toISOString(),
          nowIso(),
          job.id
        );
      this.options.onError?.(err, { id: job.id, kind: job.kind, attempt });
    }
    return true;
  }

  /** Counts by status, for health checks and tests. */
  counts(): Record<'queued' | 'running' | 'done' | 'failed', number> {
    const rows = this.db.prepare('SELECT status, COUNT(*) AS n FROM jobs GROUP BY status').all() as Array<{ status: string; n: number }>;
    const out = { queued: 0, running: 0, done: 0, failed: 0 };
    for (const r of rows) out[r.status as keyof typeof out] = Number(r.n);
    return out;
  }
}
