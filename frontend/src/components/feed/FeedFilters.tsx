import { Search } from "lucide-react";
import type { SeverityLevel } from "../../types/vulnerability";

interface FeedFiltersProps {
  severity: SeverityLevel | "all";
  source: string;
  onSeverity: (s: SeverityLevel | "all") => void;
  onSource: (v: string) => void;
}

// The backend rates incidents low, medium or high.
const FEED_SEVERITIES: SeverityLevel[] = ["low", "medium", "high"];

export function FeedFilters({
  severity,
  source,
  onSeverity,
  onSource,
}: FeedFiltersProps) {
  const options: (SeverityLevel | "all")[] = ["all", ...FEED_SEVERITIES];

  return (
    <div className="flex flex-wrap items-center gap-3">
      <div className="flex items-center gap-1">
        {options.map((opt) => (
          <button
            key={opt}
            onClick={() => onSeverity(opt)}
            className={`rounded-sm border px-2.5 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors ${
              severity === opt
                ? "border-electric bg-panel-2 text-electric"
                : "border-hairline text-secondary hover:text-primary"
            }`}
          >
            {opt}
          </button>
        ))}
      </div>

      <div className="relative">
        <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-dim" />
        <input
          value={source}
          onChange={(e) => onSource(e.target.value)}
          placeholder="filter by IP…"
          className="w-48 border border-hairline bg-panel-2 py-1.5 pl-8 pr-3 font-mono text-xs text-primary placeholder:text-dim focus:border-electric focus:outline-none"
        />
      </div>
    </div>
  );
}
