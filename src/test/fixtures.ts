import { inject, vi } from 'vitest';
import type { FullComplianceScanReport, McpServerDescriptor, MultiAgentPipelineReport } from '../../shared/types';

export interface UiFixtures {
  report: FullComplianceScanReport;
  multiAgentReport: MultiAgentPipelineReport;
  mcpServers: McpServerDescriptor[];
}

/** The real report built by globalSetup.ts (a fresh copy per call). */
export function uiFixtures(): UiFixtures {
  return JSON.parse(inject('uiFixtures')) as UiFixtures;
}

/**
 * Replaces fetch with canned JSON per path (method-agnostic); unknown paths answer 404.
 * Returns the mock so tests can inspect the calls.
 */
export function mockFetch(routes: Record<string, unknown>) {
  const fn = vi.fn(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), 'http://localhost');
    if (url.pathname in routes) return new Response(JSON.stringify(routes[url.pathname]), { status: 200, headers: { 'Content-Type': 'application/json' } });
    return new Response(JSON.stringify({ error: 'not mocked' }), { status: 404, headers: { 'Content-Type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fn);
  return fn;
}
