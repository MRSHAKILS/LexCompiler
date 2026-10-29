import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { getInitialClauses } from './compiler/legalCompiler.js';
import { getMcpServersCatalog, handleMcpMessage, MCP_PROTOCOL_VERSIONS } from './mcp/mcpSuite.js';

const clauses = getInitialClauses();
const call = (message: unknown, serverId = 'lex-z3-prover-mcp') => handleMcpMessage(serverId, message, clauses);

describe('MCP JSON-RPC 2.0', () => {
  it('advertises exactly the tools and resources each server serves', async () => {
    for (const server of getMcpServersCatalog()) {
      const tools = (await call({ jsonrpc: '2.0', id: 1, method: 'tools/list' }, server.id))?.result as { tools: unknown[] };
      const resources = (await call({ jsonrpc: '2.0', id: 2, method: 'resources/list' }, server.id))?.result as { resources: unknown[] };
      expect(server.toolsCount, server.id).toBe(tools.tools.length);
      expect(server.toolsCount, server.id).toBe(server.tools.length);
      expect(server.resourcesCount, server.id).toBe(resources.resources.length);
      expect(server.promptsCount, server.id).toBe(0);
    }
  });
  it('negotiates the protocol version on initialize', async () => {
    const res = await call({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } });
    expect(res?.id).toBe(1);
    expect((res?.result as { protocolVersion: string }).protocolVersion).toBe('2025-03-26');
    const latest = await call({ jsonrpc: '2.0', id: 'x', method: 'initialize', params: { protocolVersion: '1999-01-01' } });
    expect((latest?.result as { protocolVersion: string }).protocolVersion).toBe(MCP_PROTOCOL_VERSIONS[0]);
  });

  it('does not answer notifications', async () => {
    expect(await call({ jsonrpc: '2.0', method: 'notifications/initialized' })).toBeNull();
  });

  it('reports protocol errors with the right codes and echoes the request id', async () => {
    expect((await call({ jsonrpc: '2.0', id: 7, method: 'nope' }))?.error?.code).toBe(-32601);
    const unknownTool = await call({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'nope', arguments: {} } });
    expect(unknownTool?.error?.code).toBe(-32602);
    expect(unknownTool?.id).toBe(8);
    const badArgs = await call(
      { jsonrpc: '2.0', id: 9, method: 'tools/call', params: { name: 'hybrid_contextual_graph_rag_query', arguments: {} } },
      'lex-hybrid-rag-mcp'
    );
    expect(badArgs?.error?.code).toBe(-32602);
    expect((await call({ id: 1, method: 'ping' }))?.error?.code).toBe(-32600);
  });

  it('lists tools and returns structuredContent from tools/call', async () => {
    const list = await call({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const tools = (list?.result as { tools: Array<{ name: string; inputSchema: unknown }> }).tools;
    expect(tools.map((t) => t.name)).toContain('prove_repository_compliance_z3');
    const res = await call({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'prove_repository_compliance_z3', arguments: {} } });
    const result = res?.result as { isError: boolean; structuredContent: { verdicts: Array<{ status: string }> } };
    expect(result.isError).toBe(false);
    expect(result.structuredContent.verdicts.length).toBe(clauses.length);
  });

  it('serves resources', async () => {
    const list = await call({ jsonrpc: '2.0', id: 4, method: 'resources/list' });
    const uri = (list?.result as { resources: Array<{ uri: string }> }).resources[0].uri;
    const read = await call({ jsonrpc: '2.0', id: 5, method: 'resources/read', params: { uri } });
    expect((read?.result as { contents: Array<{ text: string }> }).contents[0].text.length).toBeGreaterThan(0);
  });

  it('speaks newline-delimited JSON-RPC over stdio in request order', () => {
    const input = [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } },
      { jsonrpc: '2.0', method: 'notifications/initialized' },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      { jsonrpc: '2.0', id: 3, method: 'unknown/method' },
    ]
      .map((m) => JSON.stringify(m))
      .join('\n');
    const proc = spawnSync(process.execPath, ['--import', 'tsx', 'server/mcp/stdio-server.ts', 'lex-z3-prover-mcp'], {
      input: `${input}\nnot json\n`,
      encoding: 'utf8',
      timeout: 30000,
      env: process.env,
    });
    const lines = proc.stdout.trim().split('\n').map((l) => JSON.parse(l) as { id: unknown; error?: { code: number } });
    expect(lines.map((l) => l.id)).toEqual([1, 2, 3, null]);
    expect(lines[2].error?.code).toBe(-32601);
    expect(lines[3].error?.code).toBe(-32700);
  }, 40000);
});
