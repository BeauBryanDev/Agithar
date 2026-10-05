// The verdict <-> evidence connector logic.
// Given a message's evidence refs and the active evidence id, exposes helpers
// to segment the message text and to activate/deactivate a linked claim.

import { useCallback } from "react";
import { useAnalysisStore } from "../store/useAnalysisStore";
import type { EvidenceRef } from "../types/analysis";

export interface TextSegment {
  text: string;
  evidenceId: string | null; // if set, this segment is a backed claim
}

/** Split content into plain + evidence-backed segments using claim_span offsets. */
export function segmentContent(
  content: string,
  refs: EvidenceRef[] | undefined
): TextSegment[] {
  if (!refs || refs.length === 0) {
    return [{ text: content, evidenceId: null }];
  }
  const sorted = [...refs]
    .filter((r) => r.claim_span[0] >= 0)
    .sort((a, b) => a.claim_span[0] - b.claim_span[0]);

  const segments: TextSegment[] = [];
  let cursor = 0;
  for (const ref of sorted) {
    const [start, end] = ref.claim_span;
    if (start > cursor) {
      segments.push({ text: content.slice(cursor, start), evidenceId: null });
    }
    segments.push({ text: content.slice(start, end), evidenceId: ref.id });
    cursor = end;
  }
  if (cursor < content.length) {
    segments.push({ text: content.slice(cursor), evidenceId: null });
  }
  return segments;
}

export function useEvidenceLink() {
  const activeEvidenceId = useAnalysisStore((s) => s.activeEvidenceId);
  const setActiveEvidence = useAnalysisStore((s) => s.setActiveEvidence);

  const activate = useCallback(
    (id: string | null) => setActiveEvidence(id),
    [setActiveEvidence]
  );

  return { activeEvidenceId, activate };
}
