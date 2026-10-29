import { Parser, type ReadEntry } from 'tar';
import { MAX_SOURCE_FILE_BYTES, MAX_SOURCE_FILES, sourceLanguageForPath } from '../analyzer/repoBaseline.js';
import type { TargetRepoFile } from '../../shared/types.js';

export interface TarballSources {
  files: TargetRepoFile[];
  /** More source files (or bytes) than one scan reads. */
  truncatedAtLimit: boolean;
  /** Source files over 1 MiB, which are not read. */
  skippedLargeFiles: string[];
}

/** Total source bytes one scan keeps in memory. */
const MAX_TOTAL_SOURCE_BYTES = 128 * 1024 * 1024;

/**
 * Reads the source files out of a GitHub repository tarball, in memory. Nothing is written to
 * disk and nothing is executed. Symlinks, hard links and other non-file entries are ignored, and
 * the same paths are skipped as when reading a folder (node_modules, hidden directories, …).
 */
export async function readTarballSources(archive: Buffer): Promise<TarballSources> {
  const found: Array<{ path: string; language: TargetRepoFile['language']; content: Buffer }> = [];
  const skippedLargeFiles: string[] = [];
  let totalBytes = 0;
  let overBudget = false;
  await new Promise<void>((resolve, reject) => {
    const parser = new Parser({
      strict: true,
      onReadEntry: (entry: ReadEntry) => {
        const rel = entry.type === 'File' ? repoRelativePath(entry.path) : null;
        const language = rel ? sourceLanguageForPath(rel) : null;
        if (!rel || !language) {
          entry.resume();
          return;
        }
        if (entry.size > MAX_SOURCE_FILE_BYTES) {
          skippedLargeFiles.push(rel);
          entry.resume();
          return;
        }
        if (totalBytes + entry.size > MAX_TOTAL_SOURCE_BYTES) {
          overBudget = true;
          entry.resume();
          return;
        }
        totalBytes += entry.size;
        const chunks: Buffer[] = [];
        entry.on('data', (chunk: Buffer) => chunks.push(chunk));
        entry.on('end', () => found.push({ path: rel, language, content: Buffer.concat(chunks) }));
      },
    });
    parser.on('error', reject);
    parser.on('end', () => resolve());
    parser.end(archive);
  });
  found.sort((a, b) => a.path.localeCompare(b.path));
  const kept = found.slice(0, MAX_SOURCE_FILES);
  return {
    files: kept.map((f) => ({ path: f.path, language: f.language, description: `${f.language} source file`, content: f.content.toString('utf8'), lastModified: '' })),
    truncatedAtLimit: found.length > MAX_SOURCE_FILES || overBudget,
    skippedLargeFiles: skippedLargeFiles.sort(),
  };
}

/** Drops the archive's top-level folder (`owner-repo-sha/`); rejects `..` segments. */
function repoRelativePath(entryPath: string): string | null {
  const parts = entryPath.replace(/\\/g, '/').split('/').filter((p) => p !== '' && p !== '.');
  if (parts.length < 2 || parts.some((p) => p === '..')) return null;
  return parts.slice(1).join('/');
}
