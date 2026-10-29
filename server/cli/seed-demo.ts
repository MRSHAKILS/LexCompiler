/**
 * Seeds the demo workspace. Safe to run more than once.
 *
 *   npm run seed:demo -- [--activate-builtins] [--owner-email a@x] [--legal-email b@x] [--engineer-email c@x]
 *
 * --activate-builtins approves the four built-in illustrative clauses as R-1 to R-4, so pull
 * requests can be checked before anyone has written rules in the lawyer's workspace.
 */
import { closeDb, getDb } from '../db/index.js';
import { getInitialClauses } from '../compiler/legalCompiler.js';
import { compileClauseSync } from '../product/clauses.js';
import { ProductStore, type WorkspaceRole } from '../product/store.js';

const args = process.argv.slice(2);
const flag = (name: string) => args.includes(`--${name}`);
const value = (name: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};

const WORKSPACE_NAME = value('workspace') || 'FinHealth AI';

function main() {
  const store = new ProductStore(getDb());
  const seedUser = store.upsertUser({ sub: 'system:seed', name: 'Demo seed' });
  const workspace = store.findWorkspaceByName(WORKSPACE_NAME) ?? store.createWorkspace(WORKSPACE_NAME, null, seedUser.id);
  console.log(`Workspace "${workspace.name}": ${workspace.id}`);

  for (const [name, role] of [
    ['owner-email', 'owner'],
    ['legal-email', 'legal'],
    ['engineer-email', 'engineer'],
    ['viewer-email', 'viewer'],
  ] as const) {
    const email = value(name);
    if (email) {
      store.invite(workspace.id, email, role as WorkspaceRole, seedUser.id);
      console.log(`  invited ${email} as ${role}`);
    }
  }

  for (const name of ['Klinikum Spree', 'Nodi Microfinance']) {
    store.createCounterparty(workspace.id, name);
  }
  console.log('  counterparties: Klinikum Spree, Nodi Microfinance');

  if (flag('activate-builtins')) {
    if (store.listRules(workspace.id).length > 0) {
      console.log('  rules already exist; --activate-builtins skipped');
    } else {
      for (const builtin of getInitialClauses()) {
        const key = store.nextRuleKey(workspace.id);
        const clause = compileClauseSync({
          text: builtin.rawLegalText,
          key,
          title: builtin.title,
          citation: builtin.citation,
          category: builtin.category,
          frameworkId: builtin.frameworkId,
        });
        const { version } = store.createRuleDraft({
          workspaceId: workspace.id,
          title: builtin.title,
          sourceText: builtin.rawLegalText,
          clause: { ...clause, illustrative: true },
          createdBy: seedUser.id,
        });
        store.approveRuleVersion(workspace.id, version.id, seedUser.id, { note: 'Built-in illustrative clause activated by the demo seed.' });
        console.log(`  ${key} approved: ${builtin.title}`);
      }
    }
  }

  const unlinked = store.listUnlinkedInstallations();
  const link = value('link-installation');
  if (link) {
    store.linkInstallation(Number(link), workspace.id);
    console.log(`  linked GitHub installation ${link}`);
  } else if (unlinked.length > 0) {
    console.log(`  unlinked GitHub installations: ${unlinked.map((i) => `${i.installationId} (${i.accountLogin})`).join(', ')}; pass --link-installation <id>`);
  }
  closeDb();
}

main();
