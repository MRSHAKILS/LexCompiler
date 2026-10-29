import type { LiveRegulatoryFeedItem } from '../shared/types';

/** Body of `POST /api/clauses/compile` that adds a feed item as its own clause. */
export interface FeedClauseRequest {
  clauseId: string;
  rawLegalText: string;
  frameworkId: LiveRegulatoryFeedItem['suggestedFramework'];
  citation: string;
  title: string;
  sourceUrl: string;
  amendmentLabel: string;
}

/**
 * Change notices ("Act X amends Y") carry no obligation text, so there is nothing to compile;
 * the reader should review the clauses compiled from the amended act instead.
 */
export function canIngestFeedItem(item: LiveRegulatoryFeedItem): boolean {
  return item.kind !== 'CHANGE_NOTICE' && item.excerpt.trim().length > 0;
}

/** Stable clause id per feed item, so ingesting the same item again updates its clause. */
export function feedClauseId(item: LiveRegulatoryFeedItem): string {
  return `CLAUSE-FEED-${item.id.replace(/[^A-Za-z0-9.-]+/g, '-')}`;
}

/**
 * Compiles a feed item into a clause of its own. The server infers the rule category from the
 * text, so ingesting an EU AI Act article never overwrites the retention clause.
 */
export function feedItemToClauseRequest(item: LiveRegulatoryFeedItem): FeedClauseRequest {
  return {
    clauseId: feedClauseId(item),
    rawLegalText: item.excerpt,
    frameworkId: item.suggestedFramework,
    citation: item.documentNumber,
    title: item.title.replace(/^\[Illustrative\]\s*/, ''),
    sourceUrl: item.url,
    amendmentLabel: `Ingested ${item.documentNumber} (${item.source === 'EUR_LEX' ? 'EUR-Lex' : 'Federal Register'})`,
  };
}
