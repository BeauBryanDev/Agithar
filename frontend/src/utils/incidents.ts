// Incident status -> label and color class.

import type { IncidentStatus } from "../types/feed";

const LABELS: Record<IncidentStatus, string> = {
  open: "pending",
  needs_human: "needs review",
  confirmed: "confirmed",
  false_positive: "false positive",
  closed: "closed",
};

export function statusLabel(status: IncidentStatus): string {
  return LABELS[status] ?? status;
}

/** Statuses that need a person look bright, resolved ones are quiet. */
export function statusClass(status: IncidentStatus): string {
  if (status === "needs_human") return "text-sev-high";
  if (status === "confirmed") return "text-electric";
  if (status === "open") return "text-secondary";
  return "text-dim";
}
