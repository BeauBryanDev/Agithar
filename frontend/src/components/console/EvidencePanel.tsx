import { ShieldCheck } from "lucide-react";
import type { DetectorResult } from "../../types/detector";
import { EvidenceCard } from "./EvidenceCard";
import { EmptyState } from "../common/EmptyState";

interface EvidencePanelProps {
  evidence: DetectorResult[];
  expanded: Record<string, boolean>;
  activeEvidenceId: string | null;
  onToggle: (id: string) => void;
  onHover: (id: string | null) => void;
}

export function EvidencePanel({
  evidence,
  expanded,
  activeEvidenceId,
  onToggle,
  onHover,
}: EvidencePanelProps) {
  if (evidence.length === 0) {
    return (
      <EmptyState
        icon={<ShieldCheck className="h-8 w-8" strokeWidth={1.5} />}
        title="No detector output yet"
        hint="When detectors run, their verifiable scores appear here. Every claim on the left links to a card on this side."
      />
    );
  }

  return (
    <div className="flex flex-col gap-3 p-4">
      {evidence.map((e) => (
        <EvidenceCard
          key={e.id}
          result={e}
          expanded={!!expanded[e.id]}
          active={activeEvidenceId === e.id}
          onToggle={() => onToggle(e.id)}
          onHover={onHover}
        />
      ))}
    </div>
  );
}
