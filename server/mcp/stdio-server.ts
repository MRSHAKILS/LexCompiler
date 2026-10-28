#!/usr/bin/env node
import readline from 'node:readline';
import { getMcpServersCatalog, invokeMcpTool } from './mcpSuite.js';

const serverId = process.argv[2] || 'lex-z3-prover-mcp';
const catalog = getMcpServersCatalog();
const serverDesc = catalog.find((s) => s.id === serverId) || catalog[0];

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

rl.on('line', async (line) => {
  if (!line.trim()) return;
  try {
    const req = JSON.parse(line);
    if (req.method === 'initialize') {
      process.stdout.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: req.id,
          result: {
            protocolVersion: '2025-03-26',
            serverInfo: { name: serverDesc.name, version: serverDesc.version },
            capabilities: { tools: {}, resources: {}, prompts: {} },
          },
        }) + '\n'
      );
    } else if (req.method === 'tools/list') {
      process.stdout.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: req.id,
          result: { tools: serverDesc.tools },
        }) + '\n'
      );
    } else if (req.method === 'tools/call') {
      const res = await invokeMcpTool(
        serverDesc.id,
        req.params?.name,
        req.params?.arguments || {}
      );
      process.stdout.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: req.id,
          result: res.jsonRpcResponse.result,
        }) + '\n'
      );
    }
  } catch (err) {
    process.stdout.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: String(err) },
      }) + '\n'
    );
  }
});
