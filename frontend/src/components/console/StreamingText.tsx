import { MarkdownText } from "./MarkdownText";
import { segmentContent } from "../../hooks/useEvidenceLink";
import type { EvidenceRef } from "../../types/analysis";

interface StreamingTextProps {
  content: string;
  refs?: EvidenceRef[];
  streaming?: boolean;
  activeEvidenceId: string | null;
  onHoverClaim: (id: string | null) => void;
}

/**
 * Renders analysis text in the sans face, with evidence-backed claims marked
 * by a neon left-edge and interactive on hover for the connector.
 */
export function StreamingText({
  content,
  refs,
  streaming,
  activeEvidenceId,
  onHoverClaim,
}: StreamingTextProps) {
  // Evidence claims are character spans over the raw text, so they only
  // work on plain text. Replies without claims are rendered as markdown.
  if (!refs || refs.length === 0) {
    return <MarkdownText content={content} streaming={streaming} />;
  }

  const segments = segmentContent(content, refs);

  return (
    <p className="whitespace-pre-wrap text-base leading-relaxed text-primary">
      {segments.map((seg, i) => {
        if (!seg.evidenceId) {
          return <span key={i}>{seg.text}</span>;
        }
        const active = activeEvidenceId === seg.evidenceId;
        return (
          <mark
            key={i}
            data-evidence-claim={seg.evidenceId}
            onMouseEnter={() => onHoverClaim(seg.evidenceId)}
            onMouseLeave={() => onHoverClaim(null)}
            className={`cursor-help rounded-sm border-l-2 bg-transparent px-1 text-primary transition-colors ${
              active
                ? "border-neon bg-panel-2 text-neon"
                : "border-electric"
            }`}
          >
            {seg.text}
          </mark>
        );
      })}
      {streaming && <span className="aegis-cursor" />}
    </p>
  );
}
