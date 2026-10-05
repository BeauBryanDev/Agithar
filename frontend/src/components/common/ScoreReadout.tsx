import type { SeverityLevel } from "../../types/vulnerability";
import { severityTextClass } from "../../utils/severity";

interface ScoreReadoutProps {
  value: string; // pre-formatted
  label?: string;
  severity?: SeverityLevel; // colors the value
  size?: "md" | "lg" | "xl";
}

const sizes = {
  md: "text-2xl",
  lg: "text-4xl",
  xl: "text-5xl",
};

/** Large mono instrument value — a real detector output, presented as a readout. */
export function ScoreReadout({
  value,
  label,
  severity,
  size = "lg",
}: ScoreReadoutProps) {
  const color = severity ? severityTextClass(severity) : "text-electric";
  return (
    <div className="flex flex-col">
      {label && (
        <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
          {label}
        </span>
      )}
      <span
        className={`font-mono font-semibold leading-none tabular-nums ${sizes[size]} ${color}`}
      >
        {value}
      </span>
    </div>
  );
}
