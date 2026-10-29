import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterAll, describe, expect, it } from 'vitest';
import { ExternalMcpClient, closeExternalClients, loadExternalMcpConfig, probeExternalMcpServers } from './mcp/externalClients.js';

afterAll(() => closeExternalClients());

describe('external MCP clients', () => {
  it('stdio: handshakes, lists and calls tools on a spawned MCP server', async () => {
    // LexCompiler's own stdio server stands in for an external one.
    const client = await ExternalMcpClient.connect('lex-z3', { command: process.execPath, args: ['--import', 'tsx', 'server/mcp/stdio-server.ts', 'lex-z3-prover-mcp'] }, 60_000);
    try {
      expect(client.init.protocolVersion).toBe('2025-06-18');
      const tools = await client.listTools();
      expect(tools.map((t) => t.name)).toContain('prove_repository_compliance_z3');
      const result = (await client.callTool('prove_repository_compliance_z3')) as { content: Array<{ text: string }> };
      expect(result.content[0].text).toContain('UNSAT_VIOLATION');
    } finally {
      client.close();
    }
  }, 90_000);

  it('streamable HTTP: handles SSE replies and the session header', async () => {
    const seen: Array<{ session?: string; method: string }> = [];
    const server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const msg = JSON.parse(body);
        seen.push({ session: req.headers['mcp-session-id'] as string | undefined, method: msg.method });
        if (msg.id === undefined) return void res.writeHead(202).end();
        const result = msg.method === 'initialize' ? { protocolVersion: '2025-06-18', serverInfo: { name: 'fake', version: '1' }, capabilities: {} } : msg.method === 'tools/list' ? { tools: [{ name: 'ping' }] } : { content: [{ type: 'text', text: 'pong' }] };
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Mcp-Session-Id': 'sess-1' });
        res.end(`event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', id: msg.id, result })}\n\n`);
      });
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    try {
      const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/mcp`;
      const client = await ExternalMcpClient.connect('fake', { url });
      expect(client.init.serverInfo?.name).toBe('fake');
      expect(await client.callTool('ping')).toEqual({ content: [{ type: 'text', text: 'pong' }] });
      expect(seen.map((s) => s.method)).toEqual(['initialize', 'notifications/initialized', 'tools/call']);
      expect(seen.slice(1).every((s) => s.session === 'sess-1')).toBe(true);
    } finally {
      server.close();
    }
  });

  it('reports a server ONLINE only when it answers, and expands ${VAR} in the config', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcpcfg-'));
    const file = path.join(dir, 'mcp-servers.json');
    process.env.LEXC_TEST_TOKEN = 'secret-123';
    fs.writeFileSync(file, JSON.stringify({ mcpServers: { broken: { command: 'definitely-not-a-command-xyz' }, gh: { url: 'http://127.0.0.1:9/mcp', headers: { Authorization: 'Bearer ${LEXC_TEST_TOKEN}' } } } }));
    const cfg = loadExternalMcpConfig(file);
    expect(cfg.gh.headers?.Authorization).toBe('Bearer secret-123');
    const statuses = await probeExternalMcpServers(cfg);
    expect(statuses.map((s) => [s.id, s.status])).toEqual([['broken', 'OFFLINE'], ['gh', 'OFFLINE']]);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
