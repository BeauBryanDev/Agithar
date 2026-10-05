// Reusable file-upload logic for the ingest drop zone.

import { useCallback, useState } from "react";
import { uploadFile, routeFile, type IngestResult } from "../services/ingestService";
import type { DetectorName } from "../types/detector";

export interface UploadItem {
  id: string;
  filename: string;
  size: number;
  routed_to: DetectorName | null;
  status: "classifying" | "processing" | "done" | "error";
  error?: string;
}

export function useFileUpload() {
  const [items, setItems] = useState<UploadItem[]>([]);

  const handleFiles = useCallback(async (fileList: FileList | File[]) => {
    const files = Array.from(fileList);
    for (const file of files) {
      const id = `up-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
      const routed = routeFile(file.name);
      setItems((prev) => [
        {
          id,
          filename: file.name,
          size: file.size,
          routed_to: routed,
          status: routed ? "processing" : "error",
          error: routed
            ? undefined
            : "Unsupported format — .log, NetFlow CSV, .pcap, or .eml expected",
        },
        ...prev,
      ]);

      if (!routed) continue;

      try {
        const result: IngestResult = await uploadFile(file);
        setItems((prev) =>
          prev.map((it) =>
            it.id === id
              ? { ...it, status: "done", routed_to: result.routed_to }
              : it
          )
        );
      } catch (err) {
        setItems((prev) =>
          prev.map((it) =>
            it.id === id
              ? {
                  ...it,
                  status: "error",
                  error: err instanceof Error ? err.message : "Upload failed",
                }
              : it
          )
        );
      }
    }
  }, []);

  const clear = useCallback(() => setItems([]), []);

  return { items, handleFiles, clear };
}
