// POST /ingest: the raw file is the request body (no multipart, so the
// server never writes a temporary file). All ingest network I/O lives here.

import { apiClient, apiPath, isGuestSession } from "./apiClient";
import type { IngestResult } from "../types/ingest";

export const ALLOWED_EXTENSIONS = [".log", ".txt", ".csv"] as const;
// The server enforces its own cap; this one only saves a pointless upload.
export const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;
// The public demo accepts much smaller files.
export const GUEST_MAX_UPLOAD_BYTES = 1024 * 1024;

/** The largest file this session may send, in bytes. */
export function maxUploadBytes(): number {
  return isGuestSession() ? GUEST_MAX_UPLOAD_BYTES : MAX_UPLOAD_BYTES;
}
const ANALYSIS_TIMEOUT_MS = 120_000;

/** The reason a file cannot be sent, or null when it looks acceptable. */
export function checkFile(file: File): string | null {
  const lower = file.name.toLowerCase();
  if (!ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext))) {
    return "Unsupported file type. Use .log, .txt or .csv.";
  }
  if (file.size === 0) return "The file is empty.";
  if (file.size > maxUploadBytes()) {
    return `The file is larger than ${maxUploadBytes() / (1024 * 1024)} MB.`;
  }
  return null;
}

export async function uploadFile(
  file: File,
  onProgress?: (fraction: number) => void
): Promise<IngestResult> {
  const { data } = await apiClient.post<IngestResult>(apiPath("/ingest"), file, {
    params: { filename: file.name },
    headers: { "Content-Type": "application/octet-stream" },
    timeout: ANALYSIS_TIMEOUT_MS,
    onUploadProgress: (e) => {
      if (e.total) onProgress?.(e.loaded / e.total);
    },
  });
  return data;
}
