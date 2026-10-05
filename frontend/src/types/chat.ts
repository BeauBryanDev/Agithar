// Chat contract: POST /chat/stream sends server-sent events.

import type { EvidenceRef } from "./analysis";
import type { DetectorResult } from "./detector";

export interface ChatMessage {
  id: string;
  role: "analyst" | "system";
  content: string;
  evidence_refs: EvidenceRef[];
  created_at: string; // ISO 8601
}

export interface ChatReply {
  session_id: string;
  message: ChatMessage;
  evidence: DetectorResult[];
}

export type ChatStreamEvent =
  | { type: "status"; text: string } // what Agithar is doing now
  | { type: "token"; text: string } // the answer so far (cumulative)
  | { type: "evidence"; evidence: DetectorResult[] }
  | { type: "error"; text: string }
  | { type: "done"; reply: ChatReply };
