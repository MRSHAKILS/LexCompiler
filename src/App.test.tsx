// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { expectNamedControls } from './test/a11y';
import { mockFetch, uiFixtures } from './test/fixtures';

const fx = uiFixtures();

function routes() {
  return {
    '/api/state': fx.report,
    '/api/regulations/live-feed': { items: [] },
    '/api/ai-heavy/overview': { mcpServers: fx.mcpServers, multiAgentReport: fx.multiAgentReport, tokenBenchmark: null, defaultRagReport: null, promptLibrary: [] },
    '/api/services/mesh': { ollamaModels: [] },
    '/api/remediation/github': { enabled: false },
    '/api/repo/reset': fx.report,
  };
}

beforeEach(() => {
  window.history.replaceState(null, '', '/');
  mockFetch(routes());
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function renderDashboard() {
  const view = render(<App />);
  expect(screen.getByRole('status').textContent).toMatch(/Initializing LexCompiler/);
  await screen.findByRole('navigation', { name: 'Workspace modules' });
  return view;
}

describe('dashboard', () => {
  it('renders the real scan: repository, commit and the Z3 verdict', async () => {
    await renderDashboard();
    expect(screen.getAllByText(fx.report.repositoryName).length).toBeGreaterThan(0);
    const verdict = screen.getByRole('status', { name: 'Z3 verdict' });
    expect(verdict.textContent).toContain(`UNSAT · ${fx.report.violatedClausesCount} VIOLATIONS`);
  });

  it('marks the active module and switches modules with Ctrl/⌘ + digit', async () => {
    await renderDashboard();
    const nav = screen.getByRole('navigation', { name: 'Workspace modules' });
    const current = () => within(nav).getAllByRole('button').filter((b) => b.getAttribute('aria-current') === 'page');
    expect(current().map((b) => b.getAttribute('aria-label'))).toEqual(['Law-to-AST Split Studio']);
    expect(within(nav).getByRole('button', { name: 'Law-to-AST Split Studio' }).getAttribute('aria-keyshortcuts')).toBe('Control+1 Meta+1');

    fireEvent.keyDown(window, { key: '4', ctrlKey: true });
    await waitFor(() => expect(current().map((b) => b.getAttribute('aria-label'))).toEqual(['12-MCP & 6-Agent Plane']));
    fireEvent.keyDown(window, { key: '1', metaKey: true });
    await waitFor(() => expect(current().map((b) => b.getAttribute('aria-label'))).toEqual(['Law-to-AST Split Studio']));
    // Plain digits (typing in an editor) and Ctrl+Shift+digit are left alone.
    fireEvent.keyDown(window, { key: '4' });
    fireEvent.keyDown(window, { key: '4', ctrlKey: true, shiftKey: true });
    expect(current().map((b) => b.getAttribute('aria-label'))).toEqual(['Law-to-AST Split Studio']);
  });

  it('exposes the corpus switch as pressed toggles and announces results in a live region', async () => {
    await renderDashboard();
    const group = screen.getByRole('group', { name: 'Statutory corpus' });
    expect(within(group).getByRole('button', { name: 'EN (Global)' }).getAttribute('aria-pressed')).toBe('true');
    expect(within(group).getByRole('button', { name: 'বাংলা (BD Laws)' }).getAttribute('aria-pressed')).toBe('false');

    const live = screen.getAllByRole('status').find((el) => el.getAttribute('aria-live') === 'polite')!;
    expect(live.textContent).toBe('');
    fireEvent.click(screen.getByRole('button', { name: /1\. Baseline \(30d\)/ }));
    await waitFor(() => expect(live.textContent).toMatch(/Legacy 30-Day/));
  });

  it('names every control on the main workspace', async () => {
    const { container } = await renderDashboard();
    expectNamedControls(container);
  });
});