import { createRequire } from 'node:module';
import path from 'node:path';
import treeSitter from '@vscode/tree-sitter-wasm';
import type { RuleCategory, TargetRepoFile } from '../../shared/types.js';

type TsLanguage = Awaited<ReturnType<typeof treeSitter.Language.load>>;

const require = createRequire(import.meta.url);
const WASM_DIR = path.join(path.dirname(require.resolve('@vscode/tree-sitter-wasm/package.json')), 'wasm');

let ready: Promise<{ python: TsLanguage; typescript: TsLanguage }> | null = null;

function languages() {
  ready ??= (async () => {
    await treeSitter.Parser.init();
    const [python, typescript] = await Promise.all([
      treeSitter.Language.load(path.join(WASM_DIR, 'tree-sitter-python.wasm')),
      treeSitter.Language.load(path.join(WASM_DIR, 'tree-sitter-typescript.wasm')),
    ]);
    return { python, typescript };
  })();
  return ready;
}

/**
 * Real Tree-sitter queries (Python / TypeScript grammars) that locate the code
 * constructs a clause constrains. Sections are introduced by `;; @language <name>`.
 */
export function treeSitterQueriesFor(category: RuleCategory): string {
  const pyTtl = `(assignment
  left: (identifier) @name (#match? @name "(TTL|ttl|RETENTION|retention|EXPIR|expir|PURGE|purge)")
  right: (_) @value)`;
  const pyKms = `(assignment
  left: (identifier) @name (#match? @name "(KMS|kms)")
  right: [(true) (false)] @value)
(call
  function: (identifier) @encrypt_fn (#match? @encrypt_fn "encrypt"))`;
  const pyLog = `(call
  function: (attribute
    object: (_) @logger
    attribute: (identifier) @method (#match? @method "^(info|warning|warn|error|debug|exception|critical)$"))
  arguments: (argument_list) @args)`;
  const tsConst = (pattern: string) => `(variable_declarator
  name: (identifier) @name (#match? @name "${pattern}")
  value: (_) @value)`;
  const embeddedDdl = `((string) @ddl (#match? @ddl "CREATE TABLE"))`;
  switch (category) {
    case 'RETENTION_AND_TENANT_KMS':
      return `;; @language python\n${pyTtl}\n${pyKms}\n;; @language typescript\n${tsConst('(TTL|ttl|RETENTION|retention)')}`;
    case 'PII_LOGGING_BAN':
      return `;; @language python\n${pyLog}\n;; @language typescript\n(call_expression
  function: (member_expression
    object: (identifier) @logger (#match? @logger "^(console|logger|log)$")
    property: (property_identifier) @method)
  arguments: (arguments) @args)`;
    case 'AI_HUMAN_IN_THE_LOOP':
      return `;; @language typescript\n${tsConst('(CONFIDENCE|THRESHOLD|confidence|threshold|HUMAN|human|AUDIT|audit)')}\n;; @language python\n${pyTtl.replace(/TTL\|ttl\|RETENTION\|retention\|EXPIR\|expir\|PURGE\|purge/, 'CONFIDENCE|THRESHOLD|confidence|threshold|HUMAN|AUDIT')}`;
    case 'CROSS_BORDER_TRANSFER':
      return `;; @language typescript\n(variable_declarator
  name: (identifier) @name
  value: (string) @value (#match? @value "(us|eu|ap|ca|sa|me|af)-[a-z]+-[0-9]"))\n;; @language python\n(assignment
  left: (identifier) @name
  right: (string) @value (#match? @value "(us|eu|ap|ca|sa|me|af)-[a-z]+-[0-9]"))`;
    case 'ENCRYPTION_AT_REST':
    case 'RIGHT_TO_ERASURE_CASCADE':
      return `;; @language python\n${embeddedDdl}\n${pyKms}\n;; @language typescript\n((template_string) @ddl (#match? @ddl "CREATE TABLE"))`;
  }
}

export interface StructuralMatch {
  filePath: string;
  language: 'python' | 'typescript';
  line: number;
  captures: Record<string, string>;
}

function splitSections(queries: string): Array<{ language: 'python' | 'typescript'; source: string }> {
  const sections: Array<{ language: 'python' | 'typescript'; source: string }> = [];
  for (const block of queries.split(/^;; @language /m).filter((b) => b.trim())) {
    const [lang, ...rest] = block.split('\n');
    const language = lang.trim();
    if (language === 'python' || language === 'typescript') sections.push({ language, source: rest.join('\n') });
  }
  return sections;
}

/** Executes a clause's Tree-sitter queries over the repository's Python and TypeScript files. */
export async function runTreeSitterQueries(queries: string, files: TargetRepoFile[]): Promise<StructuralMatch[]> {
  const langs = await languages();
  const parser = new treeSitter.Parser();
  const matches: StructuralMatch[] = [];
  for (const section of splitSections(queries)) {
    const lang = langs[section.language];
    const query = new treeSitter.Query(lang, section.source);
    parser.setLanguage(lang);
    for (const file of files.filter((f) => f.language === section.language)) {
      const tree = parser.parse(file.content);
      if (!tree) continue;
      for (const m of query.matches(tree.rootNode)) {
        const captures: Record<string, string> = {};
        for (const c of m.captures) captures[c.name] = c.node.text.slice(0, 200);
        matches.push({ filePath: file.path, language: section.language, line: (m.captures[0]?.node.startPosition.row ?? 0) + 1, captures });
      }
      tree.delete();
    }
    query.delete();
  }
  parser.delete();
  return matches;
}
