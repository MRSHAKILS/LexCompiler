// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { IdeRemediationDrawer } from './IdeRemediationDrawer';
import { expectNamedControls } from '../test/a11y';
import { mockFetch, uiFixtures } from '../test/fixtures';

const { report } = uiFixtures();
const violated = report.architectureGraph.nodes.find((n) => n.status === 'VIOLATION' && report.files.some((f) => f.path === n.filePath))!;

function renderDrawer(overrides: Partial<React.ComponentProps<typeof IdeRemediationDrawer>> = {}) {
  const props = {
    selectedNode: violated,
    files: report.files,
    proofs: report.proofs,
    remediationPR: report.remediationPR,
    merkleAuditRoot: report.merkleAuditRoot,
    isApplyingPatch: false,
    onApplyNodePatch: vi.fn(),
    onApplyFullPR: vi.fn(),
    onSaveFileEdit: vi.fn(),
    ...overrides,
  };
  return { props, ...render(<IdeRemediationDrawer {...props} />) };
}

beforeEach(() => {
  mockFetch({ '/api/remediation/github': { enabled: false } });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('IDE remediation drawer', () => {
  it('shows the real violation and synthesized patch for the selected node', async () => {
    renderDrawer();
    expect(screen.getByText(/CRIMSON NODE · UNSAT/)).toBeTruthy();
    const loc = report.proofs.flatMap((p) => p.offendingLocations).find((l) => l.nodeId === violated.id || l.filePath === violated.filePath)!;
    expect(screen.getAllByText(new RegExp(`AT ${loc.filePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`)).length).toBeGreaterThan(0);
    expect(screen.getByRole('region', { name: /Unified diff of/ })).toBeTruthy();
    await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/sandbox/verify-runtime'));
  });

  it('implements the tabs pattern: roving tabIndex, arrows, Home/End, labelled panel', async () => {
    renderDrawer();
    const tablist = screen.getByRole('tablist', { name: 'Remediation views' });
    const tabs = screen.getAllByRole('tab');
    expect(tabs).toHaveLength(5);
    expect(tabs.map((t) => t.tabIndex)).toEqual([0, -1, -1, -1, -1]);
    expect(tabs[0].getAttribute('aria-selected')).toBe('true');
    expect(screen.getByRole('tabpanel').getAttribute('aria-labelledby')).toBe(tabs[0].id);

    act(() => tabs[0].focus());
    fireEvent.keyDown(tablist, { key: 'ArrowRight' });
    await waitFor(() => expect(screen.getByRole('tab', { selected: true })).toBe(tabs[1]));
    expect(document.activeElement).toBe(tabs[1]);

    fireEvent.keyDown(tablist, { key: 'End' });
    await waitFor(() => expect(screen.getByRole('tab', { selected: true })).toBe(tabs[4]));
    expect(screen.getByRole('list', { name: 'File patches' })).toBeTruthy();

    fireEvent.keyDown(tablist, { key: 'ArrowRight' }); // wraps
    await waitFor(() => expect(screen.getByRole('tab', { selected: true })).toBe(tabs[0]));
    fireEvent.keyDown(tablist, { key: 'ArrowLeft' });
    await waitFor(() => expect(screen.getByRole('tab', { selected: true })).toBe(tabs[4]));
    fireEvent.keyDown(tablist, { key: 'Home' });
    await waitFor(() => expect(document.activeElement).toBe(tabs[0]));
    expect(screen.getByRole('tabpanel').getAttribute('aria-labelledby')).toBe(tabs[0].id);
  });

  it('edits the selected file through a labelled editor and saves the edited content', () => {
    const { props } = renderDrawer();
    fireEvent.click(screen.getByRole('tab', { name: /Live Repo Source Editor/ }));
    const editor = screen.getByRole('textbox', { name: /Editing live disk file/ }) as HTMLTextAreaElement;
    const file = report.files.find((f) => f.path === violated.filePath)!;
    const lf = file.content.replace(/\r\n/g, '\n');
    expect(editor.value).toBe(lf);
    fireEvent.change(editor, { target: { value: `${lf}\n# reviewed` } });
    fireEvent.click(screen.getByRole('button', { name: /Save Commit/ }));
    expect(props.onSaveFileEdit).toHaveBeenCalledWith(file.path, `${file.content}${file.content.includes('\r\n') ? '\r\n' : '\n'}# reviewed`);
  });

  it('saves CRLF files with CRLF line endings although the textarea normalises them', () => {
    const crlf = { ...report.files.find((f) => f.path === violated.filePath)!, content: 'a = 1\r\nb = 2\r\n' };
    const { props } = renderDrawer({ files: report.files.map((f) => (f.path === crlf.path ? crlf : f)) });
    fireEvent.click(screen.getByRole('tab', { name: /Live Repo Source Editor/ }));
    fireEvent.click(screen.getByRole('button', { name: /Save Commit/ }));
    expect(props.onSaveFileEdit).toHaveBeenCalledWith(crlf.path, 'a = 1\r\nb = 2\r\n');
  });

  it('lists every proof with its witness, and names every control', () => {
    const { container } = renderDrawer();
    fireEvent.click(screen.getByRole('tab', { name: /Z3 Witness/ }));
    for (const p of report.proofs) expect(screen.getByRole('region', { name: `${p.citation} proof` })).toBeTruthy();
    expectNamedControls(container);
  });
});