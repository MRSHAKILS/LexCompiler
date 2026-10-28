/**
 * EUR-Lex / CELLAR access: amendments to tracked acts via the Publications Office SPARQL
 * endpoint, and official article text from EUR-Lex's HTML rendering.
 */
export const CELLAR_SPARQL = process.env.LEXCOMPILER_EURLEX_SPARQL_URL || 'https://publications.europa.eu/webapi/rdf/sparql';
export const EURLEX_HTML = process.env.LEXCOMPILER_EURLEX_HTML_URL || 'https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/';

/** Acts amending or correcting a CELEX number, newest first. */
export function amendmentsQuery(celex: string, limit = 10): string {
  if (!/^[0-9A-Z()]+$/.test(celex)) throw new Error(`invalid CELEX number ${celex}`);
  return `PREFIX cdm: <http://publications.europa.eu/ontology/cdm#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
SELECT DISTINCT ?celex ?date ?relation WHERE {
  ?target cdm:resource_legal_id_celex "${celex}"^^xsd:string .
  { ?act cdm:resource_legal_amends_resource_legal ?target . BIND("amends" AS ?relation) }
  UNION
  { ?act cdm:resource_legal_corrects_resource_legal ?target . BIND("corrects" AS ?relation) }
  ?act cdm:resource_legal_id_celex ?celex .
  OPTIONAL { ?act cdm:work_date_document ?date }
} ORDER BY DESC(?date) LIMIT ${limit}`;
}

export interface EurLexAmendment {
  targetCelex: string;
  celex: string;
  date: string | null;
  relation: 'amends' | 'corrects';
  url: string;
}

export async function fetchEurLexAmendments(celexList: string[], fetchImpl: typeof fetch = fetch, timeoutMs = 4000): Promise<EurLexAmendment[]> {
  const out: EurLexAmendment[] = [];
  for (const celex of celexList) {
    const url = `${CELLAR_SPARQL}?${new URLSearchParams({ query: amendmentsQuery(celex), format: 'application/sparql-results+json' })}`;
    const res = await fetchImpl(url, { headers: { Accept: 'application/sparql-results+json' }, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`CELLAR SPARQL returned ${res.status}`);
    const data = (await res.json()) as { results?: { bindings?: Array<Record<string, { value: string }>> } };
    for (const b of data.results?.bindings || []) {
      out.push({
        targetCelex: celex,
        celex: b.celex.value,
        date: b.date?.value?.slice(0, 10) ?? null,
        relation: b.relation?.value === 'corrects' ? 'corrects' : 'amends',
        url: `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:${b.celex.value}`,
      });
    }
  }
  return out;
}

const decode = (s: string) =>
  s
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;|&#160;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&rsquo;|&lsquo;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();

/** Official text of one article: EUR-Lex marks articles as <div class="eli-subdivision" id="art_N">. */
export function extractArticle(html: string, article: number): { title: string; text: string } | null {
  const start = html.search(new RegExp(`id="art_${article}"`));
  if (start < 0) return null;
  const rest = html.slice(start);
  const next = rest.slice(1).search(/id="art_\d+"/);
  const block = next >= 0 ? rest.slice(0, next + 1) : rest.slice(0, 20000);
  const heading = /class="oj-ti-art"[^>]*>([\s\S]*?)<\/p>/.exec(block)?.[1];
  const subtitle = /class="oj-sti-art"[^>]*>([\s\S]*?)<\/p>/.exec(block)?.[1];
  const paragraphs = [...block.matchAll(/<p class="oj-normal"[^>]*>([\s\S]*?)<\/p>/g)].map((m) => decode(m[1])).filter(Boolean);
  if (!paragraphs.length) return null;
  return { title: [heading, subtitle].filter(Boolean).map((t) => decode(t!)).join(' — '), text: paragraphs.join(' ') };
}

export async function fetchEurLexArticle(celex: string, article: number, fetchImpl: typeof fetch = fetch, timeoutMs = 4000): Promise<{ title: string; text: string; url: string } | null> {
  const url = `${EURLEX_HTML}?uri=CELEX:${celex}`;
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) return null;
  const found = extractArticle(await res.text(), article);
  return found ? { ...found, url: `https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:${celex}#art_${article}` } : null;
}
