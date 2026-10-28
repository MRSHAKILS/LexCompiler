import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { analyzeFullRepositoryAsync } from './analyzer/astAnalyzer.js';
import { readTargetRepoFiles } from './analyzer/repoBaseline.js';
import { runAgent } from './agents/agentRuntime.js';
import { llmConfigFor } from './agents/llmClient.js';
import { buildMultiAgentExecutionReport } from './agents/multiAgentOrchestrator.js';
import { getInitialClauses } from './compiler/legalCompiler.js';
import { verifyRepositoryAgainstClauses } from './prover/z3Engine.js';

/** Scripted LLM: first asks for a tool, then answers using the tool result it received. */
function fakeLlm(protocol: 'openai' | 'anthropic', opts: { badFirstAnswer?: boolean } = {}) {
  const requests: Array<Record<string, unknown>> = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const json = JSON.parse(body);
      requests.push(json);
      const n = requests.length;
      const toolName = (protocol === 'openai' ? json.tools?.[0]?.function?.name : json.tools?.[0]?.name) as string;
      const sawTool = JSON.stringify(json.messages).includes('UNSAT_VIOLATION');
      const answer = opts.badFirstAnswer && n === 2 ? 'not json' : JSON.stringify({ summary: sawTool ? 'Z3 refutes the clauses.' : 'No data.', keyFacts: sawTool ? ['UNSAT_VIOLATION'] : [], confidence: 0.9 });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (protocol === 'openai') {
        const message = n === 1 ? { role: 'assistant', content: null, tool_calls: [{ id: 'c1', type: 'function', function: { name: toolName, arguments: '{}' } }] } : { role: 'assistant', content: answer };
        res.end(JSON.stringify({ choices: [{ message, finish_reason: n === 1 ? 'tool_calls' : 'stop' }], usage: { prompt_tokens: 100, completion_tokens: 10, prompt_tokens_details: { cached_tokens: n > 1 ? 80 : 0 } } }));
      } else {
        const content = n === 1 ? [{ type: 'tool_use', id: 'tu1', name: toolName, input: {} }] : [{ type: 'text', text: answer }];
        res.end(JSON.stringify({ content, stop_reason: n === 1 ? 'tool_use' : 'end_turn', usage: { input_tokens: 20, output_tokens: 10, cache_read_input_tokens: n > 1 ? 80 : 0, cache_creation_input_tokens: n === 1 ? 80 : 0 } }));
      }
    });
  });
  return { server, requests, start: () => new Promise<string>((r) => server.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${(server.address() as AddressInfo).port}`))) };
}

describe('LLM agent runtime', () => {
  it.each(['openai', 'anthropic'] as const)('%s: the model calls a real MCP tool and answers from its result', async (protocol) => {
    const llm = fakeLlm(protocol);
    const baseUrl = await llm.start();
    try {
      const run = await runAgent({
        agentId: 'agent-z3-formal-critic',
        role: 'You are the Z3 critic.',
        task: 'Prove the repository.',
        mcpServerId: 'lex-z3-prover-mcp',
        clauses: getInitialClauses(),
        llm: { provider: protocol, model: 'fake', baseUrl, apiKey: 'k' },
      });
      expect(run.toolCalls[0]).toMatchObject({ name: 'prove_repository_compliance_z3', ok: true });
      expect(run.output).toEqual({ summary: 'Z3 refutes the clauses.', keyFacts: ['UNSAT_VIOLATION'], confidence: 0.9 });
      expect(run.usage.cachedPromptTokens).toBe(80);
      if (protocol === 'anthropic') {
        expect(llm.requests[0].system).toEqual([expect.objectContaining({ cache_control: { type: 'ephemeral' } })]);
        expect(run.usage.cacheWriteTokens).toBe(80);
      }
    } finally {
      llm.server.close();
    }
  });

  it('asks once for a corrected answer when the output is invalid', async () => {
    const llm = fakeLlm('openai', { badFirstAnswer: true });
    const baseUrl = await llm.start();
    try {
      const run = await runAgent({ agentId: 'a', role: 'r', task: 't', mcpServerId: 'lex-z3-prover-mcp', clauses: getInitialClauses(), llm: { provider: 'openai', model: 'fake', baseUrl } });
      expect(run.turns).toBe(3);
      expect(JSON.stringify(llm.requests[2].messages)).toContain('Your answer is invalid');
    } finally {
      llm.server.close();
    }
  });

  it('reads per-agent configuration with a global fallback', () => {
    const env = { LEXCOMPILER_LLM_MODEL: 'gpt-4o', LEXCOMPILER_AGENT_Z3_FORMAL_CRITIC_MODEL: 'deepseek-reasoner', LEXCOMPILER_AGENT_Z3_FORMAL_CRITIC_BASE_URL: 'https://api.deepseek.com/v1' };
    expect(llmConfigFor('agent-z3-formal-critic', env)).toMatchObject({ model: 'deepseek-reasoner', baseUrl: 'https://api.deepseek.com/v1', provider: 'openai' });
    expect(llmConfigFor('agent-horizon-scanner', env)).toMatchObject({ model: 'gpt-4o', baseUrl: 'https://api.openai.com/v1' });
    expect(llmConfigFor('agent-horizon-scanner', {})).toBeNull();
  });
});

describe('orchestrator with configured models', () => {
  const llm = fakeLlm('openai');
  let baseUrl = '';
  beforeAll(async () => {
    baseUrl = await llm.start();
    process.env.LEXCOMPILER_AGENT_Z3_FORMAL_CRITIC_MODEL = 'fake';
    process.env.LEXCOMPILER_AGENT_Z3_FORMAL_CRITIC_BASE_URL = baseUrl;
  });
  afterAll(() => {
    delete process.env.LEXCOMPILER_AGENT_Z3_FORMAL_CRITIC_MODEL;
    delete process.env.LEXCOMPILER_AGENT_Z3_FORMAL_CRITIC_BASE_URL;
    llm.server.close();
  });

  it('runs configured agents through the LLM and the rest as direct tool calls', async () => {
    const clauses = getInitialClauses();
    const a = await analyzeFullRepositoryAsync(readTargetRepoFiles());
    const v = await verifyRepositoryAgainstClauses(clauses, a.sqlTables, a.astFindings);
    const report = await buildMultiAgentExecutionReport(clauses, a.enrichedFiles, a.sqlTables, a.astFindings, v.proofs);
    const critic = report.steps.find((s) => s.agentId === 'agent-z3-formal-critic')!;
    expect(critic).toMatchObject({ execution: 'LLM_AGENT', status: 'COMPLETED', reasoningSummary: 'Z3 refutes the clauses.' });
    expect(critic.llmUsage?.promptTokens).toBe(200);
    expect(report.steps.filter((s) => s.execution === 'DIRECT_TOOL_CALL')).toHaveLength(5);
  });
});
