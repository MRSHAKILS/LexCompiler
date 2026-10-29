import type { CrossEncoder } from './hybridRagEngine.js';

let shared: Promise<CrossEncoder | null> | null = null;

/**
 * BGE cross-encoder reranker through transformers.js (ONNX). Enabled when
 * LEXCOMPILER_RERANKER_MODEL names a model (e.g. `Xenova/bge-reranker-base`) and the
 * optional `@huggingface/transformers` package is installed; null otherwise.
 */
export function getCrossEncoder(): Promise<CrossEncoder | null> {
  shared ??= (async () => {
    const modelId = process.env.LEXCOMPILER_RERANKER_MODEL;
    if (!modelId) return null;
    const moduleName = '@huggingface/transformers';
    let tf: {
      AutoTokenizer: { from_pretrained(id: string): Promise<(a: string[], o: Record<string, unknown>) => unknown> };
      AutoModelForSequenceClassification: { from_pretrained(id: string, o?: Record<string, unknown>): Promise<(inputs: unknown) => Promise<{ logits: { sigmoid(): { tolist(): number[][] } } }>> };
      env: { allowRemoteModels: boolean; localModelPath: string };
    };
    try {
      tf = await import(/* @vite-ignore */ moduleName);
    } catch {
      console.warn(`[reranker] LEXCOMPILER_RERANKER_MODEL is set but ${moduleName} is not installed; reranking disabled.`);
      return null;
    }
    if (process.env.LEXCOMPILER_RERANKER_LOCAL_DIR) {
      tf.env.localModelPath = process.env.LEXCOMPILER_RERANKER_LOCAL_DIR;
      tf.env.allowRemoteModels = false;
    }
    const tokenizer = await tf.AutoTokenizer.from_pretrained(modelId);
    const model = await tf.AutoModelForSequenceClassification.from_pretrained(modelId, { dtype: process.env.LEXCOMPILER_RERANKER_DTYPE || 'q8' });
    return {
      name: `${modelId} cross-encoder (transformers.js)`,
      async score(query, passages) {
        if (passages.length === 0) return [];
        const inputs = tokenizer(new Array(passages.length).fill(query), { text_pair: passages, padding: true, truncation: true });
        const { logits } = await model(inputs);
        return logits.sigmoid().tolist().map((row) => row[0]);
      },
    };
  })();
  shared.catch(() => (shared = null));
  return shared;
}
