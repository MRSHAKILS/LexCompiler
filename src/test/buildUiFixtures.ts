/**
 * Child process for globalSetup.ts: scans a scratch copy of the demo fixture with the real
 * server pipeline and writes the UI fixtures to the JSON file named by argv[2]. It runs in its
 * own process so Z3's WebAssembly threads exit with it instead of competing with the tests.
 */
import fs from 'node:fs';
import { enterScratchFixtureCopy } from '../../server/cli/scratchFixture.js';

enterScratchFixtureCopy('ui');
const { getInitialClauses } = await import('../../server/compiler/legalCompiler.js');
const { buildComplianceReport } = await import('../../server/report.js');
const { buildMultiAgentExecutionReport } = await import('../../server/agents/multiAgentOrchestrator.js');
const { getMcpServersCatalog } = await import('../../server/mcp/mcpSuite.js');

const report = await buildComplianceReport(getInitialClauses(), null);
const multiAgentReport = await buildMultiAgentExecutionReport(report.clauses, report.files, report.sqlTables, report.astFindings, report.proofs);
fs.writeFileSync(process.argv[2], JSON.stringify({ report, multiAgentReport, mcpServers: getMcpServersCatalog() }));
process.exit(0);
