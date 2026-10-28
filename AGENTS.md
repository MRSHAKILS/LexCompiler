# AGENTS.md — LexCompiler AI-DLC & Multi-Agent Specification

## 1. System Overview & AI-DLC Methodology
**LexCompiler** follows a Spec-Driven AI Development Lifecycle (**BMAD-METHOD**, **GitHub Spec-Kit**, **AWS Kiro**, and **Cursor Rules**) bridging natural-language regulations (`GDPR`, `HIPAA`, `EU AI Act`, `Enterprise DPA`) and polyglot source code (`PostgreSQL DDL`, `Python 3 AST`, `TypeScript Compiler AST`) via **Microsoft Z3** and **Open Policy Agent (OPA Rego)**.

## 2. 6-Agent Neuro-Symbolic Crew
1. `agent-horizon-scanner` (**CrewAI** · `Gemini 2.5 Flash` + `DeepSeek-V3`): Polls EUR-Lex SPARQL/REST and U.S. Federal Register APIs via `lex-statute-ingest-mcp`.
2. `agent-deontic-extractor` (**DSPy** · `Claude 3.7 Sonnet`): Compiles prose into Deontic Logic $O(\varphi), F(\varphi), P(\varphi)$, SMT-LIB2, and OPA Rego via `lex-deontic-compiler-mcp`.
3. `agent-polyglot-ast-mapper` (**Hermes** · Local Ollama `Qwen-2.5-Coder-7B-GGUF`): Parses SQL DDL, Python `ast`, and TypeScript ASTs via `lex-polyglot-ast-mcp`.
4. `agent-contextual-graph-rag` (**LangGraph** · `Llama-3.3-70B` + `BGE-Reranker`): Executes Anthropic-style Contextual RAG, Semantic/Late Chunking, pgvector + BM25 RRF, and 2-hop Neo4j Cypher traversal via `lex-hybrid-rag-mcp`.
5. `agent-z3-formal-critic` (**Pydantic-AI** · `DeepSeek-R1` + `Microsoft Z3 v4.13.4`): Solves `QF_LIA` / `QF_UF` formulas, extracts minimal Unsat Cores & Counterexample Witnesses via `lex-z3-prover-mcp`.
6. `agent-remediation-pr-enforcer` (**OpenAI Swarm** · `Claude 3.7 Sonnet` + `GPT-4o`): Synthesizes CEGIS AST diffs, verifies post-patch `SAT` in Z3 sandbox, and opens PR #409 via `lex-remediation-pr-mcp`.

## 3. Verification Gates
- Every synthesized patch MUST pass the **Pre-PR Microsoft Z3 Sandbox Gate** (`UNSAT_VIOLATION` $\to$ `SAT_COMPLIANT`).
- Run `npm test` and `npm run verify:cli` before every merge.
