// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { McpAndAgentsHub } from './McpAndAgentsHub';
import { expectNamedControls } from '../test/a11y';
import { mockFetch, uiFixtures } from '../test/fixtures';

const { mcpServers, multiAgentReport } = uiFixtures();

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('agent console', () => {
  it('lists the six agent steps of the real pipeline run as labelled articles', () => {
    render(<McpAndAgentsHub mcpServers={mcpServers} multiAgentReport={multiAgentReport} onRefreshAgents={vi.fn()} />);
    expect(multiAgentReport.steps).toHaveLength(6);
    for (const step of multiAgentReport.steps) {
      const card = screen.getByRole('article', { name: `Step ${step.stepNumber}: ${step.agentName}` });
      expect(within(card).getByText(`MCP Call: ${step.mcpServerCalled} → ${step.mcpToolCalled}()`)).toBeTruthy();
    }
  });

  it('selects servers from the keyboard-reachable toggle and invokes tools with unique names', async () => {
    const [first, second] = mcpServers;
    const tool = second.tools[0];
    const fetchMock = mockFetch({
      [`/api/mcp/${second.id}/invoke`]: { serverId: second.id, toolName: tool.name, latencyMs: 3, jsonRpcRequest: { method: 'tools/call' }, jsonRpcResponse: { result: { ok: true } } },
    });
    render(<McpAndAgentsHub mcpServers={mcpServers} multiAgentReport={multiAgentReport} onRefreshAgents={vi.fn()} />);

    expect(screen.getByRole('button', { name: first.id }).getAttribute('aria-pressed')).toBe('true');
    const toggle = screen.getByRole('button', { name: second.id });
    toggle.focus();
    expect(document.activeElement).toBe(toggle);
    fireEvent.click(toggle);
    expect(toggle.getAttribute('aria-pressed')).toBe('true');
    expect(screen.getByRole('button', { name: first.id }).getAttribute('aria-pressed')).toBe('false');

    fireEvent.click(screen.getByRole('button', { name: `Invoke ${tool.name} on ${second.id}` }));
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/api/mcp/${second.id}/invoke`, expect.anything()));
    expect((await screen.findByRole('status', { name: 'JSON-RPC response' })).textContent).toContain('JSON-RPC 2.0 Response (3 ms)');
  });

  it('names every control', () => {
    const { container } = render(<McpAndAgentsHub mcpServers={mcpServers} multiAgentReport={multiAgentReport} onRefreshAgents={vi.fn()} />);
    expectNamedControls(container);
  });
});