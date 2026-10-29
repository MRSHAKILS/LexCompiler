import React, { useRef } from 'react';

/**
 * WAI-ARIA tabs with automatic activation: one tab in the tab order (roving tabIndex),
 * ArrowLeft / ArrowRight (wrapping), Home and End move focus and select.
 */
export function useRovingTabs<T extends string>(idPrefix: string, ids: readonly T[], active: T, onSelect: (id: T) => void) {
  const refs = useRef(new Map<T, HTMLButtonElement | null>());

  const select = (id: T) => {
    onSelect(id);
    refs.current.get(id)?.focus();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    const i = ids.indexOf(active);
    const next =
      e.key === 'ArrowRight' ? ids[(i + 1) % ids.length] :
      e.key === 'ArrowLeft' ? ids[(i - 1 + ids.length) % ids.length] :
      e.key === 'Home' ? ids[0] :
      e.key === 'End' ? ids[ids.length - 1] :
      null;
    if (!next) return;
    e.preventDefault();
    select(next);
  };

  const tabId = (id: T) => `${idPrefix}-tab-${id}`;
  const panelId = (id: T) => `${idPrefix}-panel-${id}`;

  return {
    tabListProps: { role: 'tablist' as const, onKeyDown },
    tabProps: (id: T) => ({
      ref: (el: HTMLButtonElement | null) => {
        refs.current.set(id, el);
      },
      id: tabId(id),
      role: 'tab' as const,
      type: 'button' as const,
      'aria-selected': id === active,
      'aria-controls': panelId(id),
      tabIndex: id === active ? 0 : -1,
      onClick: () => onSelect(id),
    }),
    panelProps: (id: T) => ({ id: panelId(id), role: 'tabpanel' as const, 'aria-labelledby': tabId(id), tabIndex: 0 }),
  };
}
