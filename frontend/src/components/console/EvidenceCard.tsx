import { ChevronDown, ChevronRight, Radar, Network } from "lucide-react";
import type { DetectorResult } from "../../types/detector";
import { ScoreReadout } from "../common/ScoreReadout";
import { Badge } from "../common/Badge";
import { formatScore, formatJSON } from "../../utils/formatters";
import { scoreToSeverity } from "../../utils/severity";
import { detectorLabel, isLogDetector } from "../../utils/detectors";

interface EvidenceCardProps {
  result: DetectorResult;
  expanded: boolean;
  active: boolean; // highlighted by the connector
  onToggle: () => void;
  onHover: (id: string | null) => void;
}

export function EvidenceCard({
  result,
  expanded,
  active,
  onToggle,
  onHover,
}: EvidenceCardProps) {
  const severity = scoreToSeverity(result.anomaly_score);
  const isLog = isLogDetector(result.detector);

  return (
    <article
      data-evidence-id={result.id}
      onMouseEnter={() => onHover(result.id)}
      onMouseLeave={() => onHover(null)}
      className={`hud-corners relative border bg-panel-2 transition-colors ${
        active
          ? "border-neon shadow-[0_0_0_1px_var(--color-neon)]"
          : "border-hairline hover:border-electric/50"
      }`}
    >
      {active && (
        <span className="aegis-fade-in pointer-events-none absolute -left-px top-4 h-6 w-1 bg-neon" />
      )}
      <header className="flex items-center justify-between border-b border-hairline px-3 py-2">
        <div className="flex items-center gap-2">
          {isLog ? (
            <Radar className="h-3.5 w-3.5 text-electric" strokeWidth={1.75} />
          ) : (
            <Network className="h-3.5 w-3.5 text-electric" strokeWidth={1.75} />
          )}
          <span className="font-mono text-xs font-medium text-primary">
            {detectorLabel(result.detector)}
          </span>
        </div>
        <Badge level={severity} label={result.verdict} />
      </header>

      <div className="flex items-end justify-between gap-4 px-3 py-3">
        <ScoreReadout
          label="anomaly score"
          value={formatScore(result.anomaly_score)}
          severity={severity}
          size="lg"
        />
        <div className="flex flex-col items-end gap-0.5 text-right">
          <span className="font-mono text-[10px] uppercase tracking-wider text-dim">
            threshold
          </span>
          <span className="font-mono text-sm text-secondary tabular-nums">
            {formatScore(result.threshold)}
          </span>
        </div>
      </div>

      {/* threshold bar */}
      <div className="px-3 pb-3">
        <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-void">
          <div
            className="absolute left-0 top-0 h-full bg-electric"
            style={{ width: `${Math.min(100, result.anomaly_score * 100)}%` }}
          />
          <div
            className="absolute top-[-2px] h-[10px] w-px bg-neon"
            style={{ left: `${Math.min(100, result.threshold * 100)}%` }}
            title="model threshold"
          />
        </div>
      </div>

      <button
        onClick={onToggle}
        className="flex w-full items-center gap-1.5 border-t border-hairline px-3 py-2 text-left font-mono text-[11px] text-secondary transition-colors hover:text-electric"
      >
        {expanded ? (
          <ChevronDown className="h-3.5 w-3.5" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5" />
        )}
        raw output
      </button>

      {expanded && (
        <pre className="max-h-56 overflow-auto border-t border-hairline bg-void px-3 py-2 font-mono text-[11px] leading-relaxed text-secondary">
          {formatJSON(result.raw)}
        </pre>
      )}
    </article>
  );
}
