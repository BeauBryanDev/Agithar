import { Sparkline } from "./Sparkline";

interface GaugeProps {
  label: string;
  value: number; // percent
  detail?: string;
  history?: number[];
}

function tone(value: number): string {
  if (value >= 90) return "text-sev-critical";
  if (value >= 70) return "text-sev-medium";
  return "text-electric";
}

function barTone(value: number): string {
  if (value >= 90) return "bg-sev-critical";
  if (value >= 70) return "bg-sev-medium";
  return "bg-electric";
}

export function Gauge({ label, value, detail, history }: GaugeProps) {
  const pct = Math.min(Math.max(value, 0), 100);
  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-baseline justify-between">
        <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
          {label}
        </span>
        <span className={`font-mono text-2xl font-semibold tabular-nums ${tone(pct)}`}>
          {pct.toFixed(1)}%
        </span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-void">
        <div className={`h-full ${barTone(pct)}`} style={{ width: `${pct}%` }} />
      </div>
      {history ? (
        <Sparkline values={history} className={tone(pct)} />
      ) : null}
      {detail && (
        <span className="font-mono text-[10px] text-secondary">{detail}</span>
      )}
    </div>
  );
}
