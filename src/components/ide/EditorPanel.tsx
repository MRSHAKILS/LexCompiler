import React, { useEffect, useState } from 'react';
import { Save } from 'lucide-react';
import type { TargetRepoFile } from '../../../shared/types';

interface EditorPanelProps {
  file: TargetRepoFile;
  onSave: (filePath: string, newContent: string) => void;
}

/** Edits a target-repo file on disk; saving commits it and re-runs the analyzer and Z3. */
export const EditorPanel: React.FC<EditorPanelProps> = ({ file, onSave }) => {
  const [code, setCode] = useState(file.content);
  useEffect(() => setCode(file.content), [file.path, file.content]);
  const editorId = `editor-${file.path.replace(/[^a-z0-9]+/gi, '-')}`;
  // A textarea normalises line breaks to \n; save with the file's own endings so an edit
  // to a CRLF file does not rewrite every line.
  const withFileEol = (text: string) => (file.content.includes('\r\n') ? text.replace(/\r?\n/g, '\r\n') : text);

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <label htmlFor={editorId} className="text-xs font-mono text-slate-300">
          Editing live disk file: <strong className="text-indigo-300">target-repo/{file.path}</strong>
        </label>
        <button
          type="button"
          onClick={() => onSave(file.path, withFileEol(code))}
          className="inline-flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono font-semibold bg-indigo-600 hover:bg-indigo-500 text-white cursor-pointer"
        >
          <Save className="w-3.5 h-3.5" aria-hidden="true" />
          Save Commit & Re-Run AST + Z3 Prover
        </button>
      </div>
      <textarea
        id={editorId}
        value={code}
        onChange={(e) => setCode(e.target.value)}
        rows={15}
        spellCheck={false}
        className="w-full rounded-lg bg-[#05070C] border border-slate-700 focus:border-indigo-400 p-3 font-mono text-xs text-slate-100 leading-relaxed"
      />
    </div>
  );
};
