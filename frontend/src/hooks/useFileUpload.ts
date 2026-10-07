// Reusable file-upload logic for the ingest drop zone. Files are analysed
// one at a time: the server runs a single analysis at a time.

import { useCallback, useRef, useState } from "react";
import { checkFile, uploadFile } from "../services/ingestService";
import type { IngestResult } from "../types/ingest";

export interface UploadItem {
  id: string;
  filename: string;
  size: number;
  status: "uploading" | "analysing" | "done" | "error";
  progress: number; // 0..1 while uploading
  result?: IngestResult;
  error?: string;
}

export function useFileUpload() {
  const [items, setItems] = useState<UploadItem[]>([]);
  const queue = useRef<Promise<void>>(Promise.resolve());

  const patch = (id: string, change: Partial<UploadItem>) =>
    setItems((prev) => prev.map((it) => (it.id === id ? { ...it, ...change } : it)));

  const run = async (id: string, file: File) => {
    try {
      const result = await uploadFile(file, (fraction) =>
        patch(id, {
          progress: fraction,
          status: fraction >= 1 ? "analysing" : "uploading",
        })
      );
      patch(id, { status: "done", result, progress: 1 });
    } catch (err) {
      patch(id, {
        status: "error",
        error: err instanceof Error ? err.message : "Upload failed",
      });
    }
  };

  const handleFiles = useCallback((fileList: FileList | File[]) => {
    for (const file of Array.from(fileList)) {
      const id = `up-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      const problem = checkFile(file);

      setItems((prev) => [
        {
          id,
          filename: file.name,
          size: file.size,
          status: problem ? "error" : "uploading",
          progress: 0,
          error: problem ?? undefined,
        },
        ...prev,
      ]);

      if (!problem) {
        queue.current = queue.current.then(() => run(id, file));
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const clear = useCallback(() => setItems([]), []);

  return { items, handleFiles, clear };
}
