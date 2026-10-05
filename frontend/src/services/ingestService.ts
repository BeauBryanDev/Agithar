// File upload / ingest routing. All ingest network I/O lives here.

import type { DetectorName } from "../types/detector";

export interface IngestResult {
  filename: string;
  size: number;
  routed_to: DetectorName;
  status: "queued" | "processing" | "done";
}

/** Classify a file by extension to the correct detector (client-side hint). */
export function routeFile(filename: string): DetectorName | null {
  const lower = filename.toLowerCase();
  if (lower.endsWith(".log")) return "log_sentinel";
  if (lower.endsWith(".eml")) return "log_sentinel";
  if (lower.endsWith(".csv") || lower.endsWith(".pcap")) return "net_guard";
  return null;
}

export async function uploadFile(file: File): Promise<IngestResult> {
  const routed = routeFile(file.name);
  if (!routed) {
    throw new Error(
      "Couldn't read that file — .log, NetFlow CSV, .pcap, or .eml expected"
    );
  }

  // The server has no POST /ingest yet: say so instead of pretending.
  throw new Error("File ingestion is not available on the server yet");
}
