import { fetchLiveRegulatoryFeed } from '../compiler/legalCompiler.js';
import type { LiveRegulatoryFeedItem } from '../../shared/types.js';
import { runNightlyScans, type NightlyDeps } from './repoScan.js';
import type { ProductStore } from './store.js';

/**
 * The daily jobs of Phase 6: store new Federal Register and EUR-Lex items, and scan every
 * repository's default branch. Bangladesh Bank circulars have no API; they are uploaded as documents.
 */

/** Fetches the feed and stores the items not seen before; returns how many were new. */
export async function refreshRegulatoryFeed(store: ProductStore, fetchFeed: () => Promise<LiveRegulatoryFeedItem[]> = () => fetchLiveRegulatoryFeed()): Promise<number> {
  const items = await fetchFeed();
  return store.addFeedItems(
    items.map((i) => ({
      id: `${i.source}:${i.documentNumber}`,
      source: i.source,
      documentNumber: i.documentNumber,
      title: i.title,
      publicationDate: i.publicationDate || null,
      agency: i.agencyOrBody || null,
      excerpt: i.excerpt,
      url: i.url || null,
      kind: i.kind ?? 'TEXT',
      illustrative: Boolean(i.illustrative),
    }))
  );
}

const DAY = 24 * 60 * 60 * 1000;

/**
 * Runs each daily job when it is due (once a day, kept across restarts in scheduler_runs).
 * Call it on start-up and then hourly.
 */
export async function runDueJobs(deps: NightlyDeps & { fetchFeed?: () => Promise<LiveRegulatoryFeedItem[]> }, now: Date = new Date()): Promise<string[]> {
  const done: string[] = [];
  if (deps.store.claimScheduledRun('regulatory-feed', DAY, now)) {
    done.push(`feed: ${await refreshRegulatoryFeed(deps.store, deps.fetchFeed)} new items`);
  }
  if (deps.store.claimScheduledRun('nightly-scans', DAY, now)) {
    const r = await runNightlyScans(deps, now);
    done.push(`nightly scans: ${r.local} local, ${r.queued} queued${r.failed.length ? `, failed: ${r.failed.join('; ')}` : ''}`);
  }
  return done;
}
