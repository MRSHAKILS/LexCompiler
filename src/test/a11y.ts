import { within } from '@testing-library/react';
import { expect } from 'vitest';

/** Every button, text box and toggle in `root` has a non-empty accessible name. */
export function expectNamedControls(root: HTMLElement) {
  const q = within(root);
  for (const role of ['button', 'textbox', 'tab', 'checkbox', 'combobox'] as const) {
    const all = q.queryAllByRole(role);
    const named = q.queryAllByRole(role, { name: /\S/ });
    const unnamed = all.filter((el) => !named.includes(el)).map((el) => el.outerHTML.slice(0, 120));
    expect(unnamed, `${role} elements without an accessible name`).toEqual([]);
  }
}
