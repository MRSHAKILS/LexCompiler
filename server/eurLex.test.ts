import { describe, expect, it } from 'vitest';
import { fetchLiveRegulatoryFeed } from './compiler/legalCompiler.js';
import { amendmentsQuery, CELLAR_RESOURCE, EURLEX_HTML, extractArticle, fetchEurLexAmendments, fetchEurLexArticle } from './regulations/eurLex.js';

// Shape of EUR-Lex's HTML rendering (eli-subdivision / oj-* classes).
const HTML = `<div class="eli-subdivision" id="art_16"><p class="oj-ti-art">Article 16</p><p class="oj-normal">Rectification.</p></div>
<div class="eli-subdivision" id="art_17"><p id="d1e2606-1-1" class="oj-ti-art">Article 17</p>
<div class="eli-title" id="art_17.tit_1"><p class="oj-sti-art">Right to erasure (&lsquo;right to be forgotten&rsquo;)</p></div>
<div id="017.001"><p class="oj-normal">1.   The data subject shall have the right to obtain from the controller the erasure of personal data concerning him or her without undue delay&nbsp;…</p></div></div>
<div class="eli-subdivision" id="art_18"><p class="oj-ti-art">Article 18</p><p class="oj-normal">Restriction.</p></div>`;

const SPARQL = { head: { vars: ['celex', 'date', 'relation'] }, results: { bindings: [{ celex: { value: '32016R0679R(02)' }, date: { value: '2018-05-23' }, relation: { value: 'corrects' } }] } };

describe('EUR-Lex / CELLAR', () => {
  it('builds a safe SPARQL query', () => {
    expect(amendmentsQuery('32016R0679')).toContain('cdm:resource_legal_id_celex "32016R0679"^^xsd:string');
    expect(() => amendmentsQuery('x" } DROP')).toThrow(/invalid CELEX/);
  });

  it('extracts official article text', () => {
    expect(extractArticle(HTML, 17)).toEqual({
      title: "Article 17 — Right to erasure ('right to be forgotten')",
      text: '1. The data subject shall have the right to obtain from the controller the erasure of personal data concerning him or her without undue delay …',
    });
    expect(extractArticle(HTML, 99)).toBeNull();
  });

  it('falls back to the CELLAR resource when EUR-Lex returns its empty 202 challenge', async () => {
    const seen: Array<{ url: string; accept?: string }> = [];
    const fake = (async (url: string, init?: RequestInit) => {
      seen.push({ url, accept: (init?.headers as Record<string, string> | undefined)?.Accept });
      if (url.startsWith(EURLEX_HTML)) return new Response(null, { status: 202 });
      if (url.startsWith(CELLAR_RESOURCE)) return new Response(HTML);
      return new Response('unavailable', { status: 503 });
    }) as unknown as typeof fetch;
    const art = await fetchEurLexArticle('32016R0679', 17, fake);
    expect(art?.title).toBe("Article 17 — Right to erasure ('right to be forgotten')");
    expect(art?.url).toBe('https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679#art_17');
    expect(seen.map((s) => s.url)).toEqual([`${EURLEX_HTML}?uri=CELEX:32016R0679`, `${CELLAR_RESOURCE}32016R0679`]);
    expect(seen[1].accept).toMatch(/application\/xhtml\+xml/);
    expect(await fetchEurLexArticle('32016R0679', 99, fake)).toBeNull();
  });

  it('parses SPARQL JSON results', async () => {
    const fake = (async () => new Response(JSON.stringify(SPARQL))) as unknown as typeof fetch;
    expect(await fetchEurLexAmendments(['32016R0679'], fake)).toEqual([
      { targetCelex: '32016R0679', celex: '32016R0679R(02)', date: '2018-05-23', relation: 'corrects', url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32016R0679R(02)' },
    ]);
  });

  it('replaces curated excerpts with official text and adds amendments', async () => {
    const fake = (async (url: string) => {
      if (url.includes('sparql')) return new Response(JSON.stringify(url.includes('32016R0679') ? SPARQL : { results: { bindings: [] } }));
      if (url.includes('CELEX:32016R0679')) return new Response(HTML);
      return new Response('unavailable', { status: 503 });
    }) as unknown as typeof fetch;
    const feed = await fetchLiveRegulatoryFeed(fake);
    const art17 = feed.find((i) => i.id === 'EURLEX-32016R0679-ART17')!;
    expect(art17).toMatchObject({ illustrative: false, agencyOrBody: 'EUR-Lex (official text)' });
    expect(art17.excerpt).toMatch(/^1\. The data subject shall have the right/);
    // The AI Act page was unavailable: its curated item stays, still marked illustrative.
    expect(feed.find((i) => i.id === 'EURLEX-32024R1689-ART14')!.illustrative).toBe(true);
    expect(feed.some((i) => i.id === 'EURLEX-CORRECTS-32016R0679R(02)')).toBe(true);
  });
});
