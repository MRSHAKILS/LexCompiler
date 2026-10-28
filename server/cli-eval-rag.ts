import { enterScratchFixtureCopy } from './cli/scratchFixture.js';

/** Retrieval evaluation over the labelled dataset; LEXCOMPILER_JUDGE_* (or LEXCOMPILER_LLM_*) adds the LLM judge. */
async function main() {
  enterScratchFixtureCopy('eval-rag');
  const { analyzeFullRepositoryAsync } = await import('./analyzer/astAnalyzer.js');
  const { readTargetRepoFiles } = await import('./analyzer/repoBaseline.js');
  const { getInitialClauses } = await import('./compiler/legalCompiler.js');
  const { verifyRepositoryAgainstClauses } = await import('./prover/z3Engine.js');
  const { executeStoreBackedRagQuery } = await import('./rag/hybridRagEngine.js');
  const { evaluateRag } = await import('./rag/evaluation.js');
  const { llmConfigFor } = await import('./agents/llmClient.js');
  const clauses = getInitialClauses();
  const a = await analyzeFullRepositoryAsync(readTargetRepoFiles());
  const v = await verifyRepositoryAgainstClauses(clauses, a.sqlTables, a.astFindings);
  const judge = llmConfigFor('agent-rag-judge');
  const report = await evaluateRag((q, k) => executeStoreBackedRagQuery(q, clauses, a.sqlTables, a.astFindings, v.proofs, k), { judge });
  console.log(`RAG evaluation: ${report.questions} labelled questions, k=${report.k}${report.judgeModel ? `, judge ${report.judgeModel}` : ' (no judge model configured)'}`);
  for (const p of report.perQuestion) {
    console.log(`  ${p.id} P@k=${p.scores.precisionAtK.toFixed(2)} R@k=${p.scores.recallAtK.toFixed(2)} MRR=${p.scores.mrr.toFixed(2)} nDCG=${p.scores.ndcgAtK.toFixed(2)}${p.judge ? ` faith=${p.judge.faithfulness.toFixed(2)} rel=${p.judge.answerRelevancy.toFixed(2)}` : ''}  ${p.query}`);
  }
  console.log(`Aggregate: ${JSON.stringify(report.aggregate)}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
