// score -> severity level mapping, and severity -> token class mapping.

import type { SeverityLevel } from "../types/vulnerability";

/** Map a normalized detector score (0..1) to a severity level. */
export function scoreToSeverity(score: number): SeverityLevel {
  if (score >= 0.9) return "critical";
  if (score >= 0.75) return "high";
  if (score >= 0.5) return "medium";
  return "low";
}

/** Map a CVSS base score (0..10) to a severity level. */
export function cvssToSeverity(base: number): SeverityLevel {
  if (base >= 9.0) return "critical";
  if (base >= 7.0) return "high";
  if (base >= 4.0) return "medium";
  return "low";
}

/** Tailwind text color class for a severity level (token-backed). */
export function severityTextClass(level: SeverityLevel): string {
  switch (level) {
    case "low":
      return "text-sev-low";
    case "medium":
      return "text-sev-medium";
    case "high":
      return "text-sev-high";
    case "critical":
      return "text-sev-critical";
  }
}

/** Tailwind background color class for a severity level (token-backed). */
export function severityBgClass(level: SeverityLevel): string {
  switch (level) {
    case "low":
      return "bg-sev-low";
    case "medium":
      return "bg-sev-medium";
    case "high":
      return "bg-sev-high";
    case "critical":
      return "bg-sev-critical";
  }
}

/** Raw token variable for chart fills (Recharts needs a value, not a class). */
export function severityVar(level: SeverityLevel): string {
  return `var(--color-sev-${level})`;
}

export const SEVERITY_ORDER: SeverityLevel[] = [
  "low",
  "medium",
  "high",
  "critical",
];
