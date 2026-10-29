import { describe, expect, it } from 'vitest';
import { canIngestFeedItem, feedClauseId, feedItemToClauseRequest } from './feedIngest';
import type { LiveRegulatoryFeedItem } from '../shared/types';

const aiAct: LiveRegulatoryFeedItem = {
  id: 'EURLEX-32024R1689-ART14',
  source: 'EUR_LEX',
  documentNumber: 'CELEX:32024R1689',
  title: '[Illustrative] Regulation (EU) 2024/1689 (EU AI Act) — Art. 14 Human Oversight',
  publicationDate: '2024-07-12',
  agencyOrBody: 'European Parliament',
  excerpt: 'High-risk AI systems shall be effectively overseen by natural persons.',
  url: 'https://eur-lex.europa.eu/eli/reg/2024/1689/oj',
  suggestedFramework: 'EU_AI_ACT',
  illustrative: true,
};

describe('feed ingestion', () => {
  it('compiles a feed item into its own clause instead of overwriting DPA §4.2', () => {
    const request = feedItemToClauseRequest(aiAct);
    expect(request.clauseId).toBe('CLAUSE-FEED-EURLEX-32024R1689-ART14');
    expect(request.clauseId).not.toBe('CLAUSE-DPA-4.2');
    expect(request).toMatchObject({
      rawLegalText: aiAct.excerpt,
      frameworkId: 'EU_AI_ACT',
      citation: 'CELEX:32024R1689',
      title: 'Regulation (EU) 2024/1689 (EU AI Act) — Art. 14 Human Oversight',
      sourceUrl: aiAct.url,
    });
  });

  it('keeps the clause id stable and safe for the API', () => {
    const notice = { ...aiAct, id: 'EURLEX-CORRECTS-32016R0679R(03)' };
    expect(feedClauseId(notice)).toBe('CLAUSE-FEED-EURLEX-CORRECTS-32016R0679R-03-');
    expect(feedClauseId(notice)).toMatch(/^[A-Za-z0-9._-]{1,120}$/);
    expect(feedClauseId(aiAct)).toBe(feedClauseId({ ...aiAct, excerpt: 'changed text' }));
  });

  it('offers no compile action for change notices', () => {
    expect(canIngestFeedItem(aiAct)).toBe(true);
    expect(
      canIngestFeedItem({ ...aiAct, kind: 'CHANGE_NOTICE', excerpt: 'Act 32026R1744 amends 32024R1689; review the clauses.' })
    ).toBe(false);
    expect(canIngestFeedItem({ ...aiAct, excerpt: '   ' })).toBe(false);
  });
});
