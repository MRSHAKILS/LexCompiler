#!/usr/bin/env node
import readline from 'node:readline';
import { getInitialClauses } from '../compiler/legalCompiler.js';
import { loadActiveClauseState } from '../state.js';
import { getMcpServersCatalog, handleMcpMessage } from './mcpSuite.js';

/**
 * MCP stdio transport: newline-delimited JSON-RPC 2.0 on stdin/stdout, processed in
 * order. Clauses come from the state the HTTP server persists, so both transports
 * verify against the same amended clauses.
 */
const serverId = process.argv[2] || 'lex-z3-prover-mcp';
if (!getMcpServersCatalog().some((s) => s.id === serverId)) {
  process.stderr.write(`Unknown MCP server "${serverId}"\n`);
  process.exit(1);
}

const rl = readline.createInterface({ input: process.stdin, terminal: false });
let queue: Promise<void> = Promise.resolve();

rl.on('line', (line) => {
  if (!line.trim()) return;
  queue = queue.then(async () => {
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      process.stdout.write(`${JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } })}\n`);
      return;
    }
    const clauses = loadActiveClauseState()?.clauses || getInitialClauses();
    const response = await handleMcpMessage(serverId, message, clauses);
    if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
  });
});
