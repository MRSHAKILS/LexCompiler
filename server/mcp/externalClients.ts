import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';

/** `mcpServers` entry, in the format Claude Desktop / Cursor use. */
export interface ExternalMcpConfig {
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
  url?: string;
  headers?: Record<string, string>;
}

export interface ExternalMcpStatus {
  id: string;
  transport: 'stdio' | 'streamable-http';
  status: 'ONLINE' | 'OFFLINE';
  serverInfo?: { name?: string; version?: string };
  protocolVersion?: string;
  tools: Array<{ name: string; description?: string }>;
  error?: string;
  checkedAt: string;
}

const PROTOCOL_VERSION = '2025-06-18';
const CLIENT_INFO = { name: 'lexcompiler', version: '1.0.0' };

interface Transport {
  request(method: string, params?: unknown): Promise<unknown>;
  notify(method: string, params?: unknown): Promise<void>;
  close(): void;
}

/** Newline-delimited JSON-RPC over a child process's stdin/stdout. */
class StdioTransport implements Transport {
  private child: ChildProcessWithoutNullStreams;
  private nextId = 1;
  private pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }>();
  private stderr = '';

  constructor(cfg: ExternalMcpConfig, private timeoutMs: number) {
    this.child = spawn(cfg.command!, cfg.args || [], { cwd: cfg.cwd, env: { ...process.env, ...(cfg.env || {}) }, stdio: ['pipe', 'pipe', 'pipe'] });
    this.child.stderr.on('data', (d) => (this.stderr = `${this.stderr}${d}`.slice(-2000)));
    this.child.on('exit', (code) => this.failAll(new Error(`process exited (${code})${this.stderr ? `: ${this.stderr.trim().slice(-300)}` : ''}`)));
    this.child.on('error', (err) => this.failAll(err));
    readline.createInterface({ input: this.child.stdout }).on('line', (line) => {
      let msg: { id?: number; result?: unknown; error?: { message: string } };
      try {
        msg = JSON.parse(line);
      } catch {
        return; // servers may log to stdout; ignore non-JSON lines
      }
      const p = typeof msg.id === 'number' ? this.pending.get(msg.id) : undefined;
      if (!p) return;
      clearTimeout(p.timer);
      this.pending.delete(msg.id!);
      if (msg.error) p.reject(new Error(msg.error.message));
      else p.resolve(msg.result);
    });
  }

  private failAll(err: Error) {
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    this.pending.clear();
  }

  request(method: string, params?: unknown): Promise<unknown> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timed out after ${this.timeoutMs} ms`));
      }, this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });
  }

  async notify(method: string, params?: unknown) {
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
  }

  close() {
    this.failAll(new Error('closed'));
    this.child.kill();
  }
}

/** MCP streamable HTTP: one POST per message; replies may be JSON or an SSE stream. */
class HttpTransport implements Transport {
  private nextId = 1;
  private sessionId?: string;

  constructor(private cfg: ExternalMcpConfig, private timeoutMs: number) {}

  private async send(body: Record<string, unknown>): Promise<unknown> {
    const res = await fetch(this.cfg.url!, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': PROTOCOL_VERSION,
        ...(this.sessionId ? { 'Mcp-Session-Id': this.sessionId } : {}),
        ...(this.cfg.headers || {}),
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    this.sessionId = res.headers.get('mcp-session-id') || this.sessionId;
    if (res.status === 202) return undefined;
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const text = await res.text();
    const messages = (res.headers.get('content-type') || '').includes('text/event-stream')
      ? text.split(/\r?\n\r?\n/).map((ev) => ev.split(/\r?\n/).filter((l) => l.startsWith('data:')).map((l) => l.slice(5).trimStart()).join('\n')).filter(Boolean).map((d) => JSON.parse(d))
      : [JSON.parse(text)];
    const reply = messages.find((m: { id?: unknown }) => m.id === body.id) as { result?: unknown; error?: { message: string } } | undefined;
    if (!reply) throw new Error('no JSON-RPC response for the request');
    if (reply.error) throw new Error(reply.error.message);
    return reply.result;
  }

  request(method: string, params?: unknown) {
    return this.send({ jsonrpc: '2.0', id: this.nextId++, method, params });
  }

  async notify(method: string, params?: unknown) {
    await this.send({ jsonrpc: '2.0', method, params });
  }

  close() {}
}

/** A connected external MCP server (initialize handshake done). */
export class ExternalMcpClient {
  private constructor(readonly id: string, readonly transport: 'stdio' | 'streamable-http', private t: Transport, readonly init: { protocolVersion?: string; serverInfo?: { name?: string; version?: string } }) {}

  static async connect(id: string, cfg: ExternalMcpConfig, timeoutMs = 20_000): Promise<ExternalMcpClient> {
    const kind = cfg.url ? 'streamable-http' : 'stdio';
    if (kind === 'stdio' && !cfg.command) throw new Error(`${id}: needs "command" or "url"`);
    const t = kind === 'stdio' ? new StdioTransport(cfg, timeoutMs) : new HttpTransport(cfg, timeoutMs);
    try {
      const init = (await t.request('initialize', { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: CLIENT_INFO })) as ExternalMcpClient['init'];
      await t.notify('notifications/initialized');
      return new ExternalMcpClient(id, kind, t, init || {});
    } catch (err) {
      t.close();
      throw err;
    }
  }

  async listTools(): Promise<Array<{ name: string; description?: string; inputSchema?: unknown }>> {
    return ((await this.t.request('tools/list', {})) as { tools?: Array<{ name: string; description?: string; inputSchema?: unknown }> })?.tools || [];
  }

  callTool(name: string, args: Record<string, unknown> = {}): Promise<unknown> {
    return this.t.request('tools/call', { name, arguments: args });
  }

  close() {
    this.t.close();
  }
}

/** Reads LEXCOMPILER_EXTERNAL_MCP_CONFIG (default ./mcp-servers.json); {} when absent. */
export function loadExternalMcpConfig(file = process.env.LEXCOMPILER_EXTERNAL_MCP_CONFIG || path.join(process.cwd(), 'mcp-servers.json')): Record<string, ExternalMcpConfig> {
  try {
    // `${VAR}` in any string is replaced from the environment, so secrets stay out of the file.
    const text = fs.readFileSync(file, 'utf8');
    const servers = (JSON.parse(text) as { mcpServers?: Record<string, ExternalMcpConfig> }).mcpServers || {};
    return JSON.parse(JSON.stringify(servers), (_k, v) => (typeof v === 'string' ? v.replace(/\$\{([A-Z0-9_]+)\}/g, (_m, name) => process.env[name] ?? '') : v));
  } catch {
    return {};
  }
}

const clients = new Map<string, Promise<ExternalMcpClient>>();

export function externalClient(id: string, config = loadExternalMcpConfig()): Promise<ExternalMcpClient> {
  const cfg = config[id];
  if (!cfg) return Promise.reject(new Error(`External MCP server "${id}" is not configured`));
  let c = clients.get(id);
  if (!c) {
    c = ExternalMcpClient.connect(id, cfg);
    c.catch(() => clients.delete(id));
    clients.set(id, c);
  }
  return c;
}

/** Connects to every configured server and lists its tools; a server is ONLINE only if both answer. */
export async function probeExternalMcpServers(config = loadExternalMcpConfig()): Promise<ExternalMcpStatus[]> {
  return Promise.all(
    Object.entries(config).map(async ([id, cfg]): Promise<ExternalMcpStatus> => {
      const transport = cfg.url ? 'streamable-http' : 'stdio';
      try {
        const client = await externalClient(id, config);
        const tools = await client.listTools();
        return { id, transport, status: 'ONLINE', serverInfo: client.init.serverInfo, protocolVersion: client.init.protocolVersion, tools: tools.map((t) => ({ name: t.name, description: t.description })), checkedAt: new Date().toISOString() };
      } catch (err) {
        clients.delete(id);
        return { id, transport, status: 'OFFLINE', tools: [], error: (err as Error).message, checkedAt: new Date().toISOString() };
      }
    })
  );
}

export function closeExternalClients(): void {
  for (const c of clients.values()) c.then((x) => x.close()).catch(() => undefined);
  clients.clear();
}
