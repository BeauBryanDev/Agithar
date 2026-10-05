// Analysis session + message contract.

import type { DetectorResult } from "./detector";

/** A claim in the analysis that is backed by evidence. */
export interface EvidenceRef {
  id: string; // matches DetectorResult.id
  claim_span: [number, number]; // [startChar, endChar] within message content
}

export type MessageRole = "analyst" | "system";

export interface AnalysisMessage {
  id: string;
  role: MessageRole;
  content: string;
  evidence_refs?: EvidenceRef[];
  streaming?: boolean;
  created_at: string; // ISO 8601
}

/** A full analysis session bundling the thread and detector evidence. */
export interface AnalysisSession {
  id: string;
  title: string;
  messages: AnalysisMessage[];
  evidence: DetectorResult[];
  created_at: string;
}
