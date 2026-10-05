// score / timestamp / bytes formatting.

/** Format a 0..1 score to a fixed 2-decimal instrument readout. */
export function formatScore(score: number): string {
  return score.toFixed(2);
}

/** Format a 0..1 score as a percentage string. */
export function formatPercent(score: number): string {
  return `${Math.round(score * 100)}%`;
}

/** Format an ISO timestamp to a compact SOC-style stamp: HH:MM:SS. */
export function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "--:--:--";
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

/** Format an ISO timestamp to date + time. */
export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "----";
  return `${d.toLocaleDateString("en-CA")} ${d.toLocaleTimeString("en-GB", {
    hour12: false,
  })}`;
}

/** Human-readable byte size. */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** Pretty-print JSON for the raw evidence blocks. */
export function formatJSON(obj: unknown): string {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}
