import type { PipelineTelemetry } from "../../types/telemetry";

function Row({
  label,
  value,
  warn = false,
}: {
  label: string;
  value: string | number;
  warn?: boolean;
}) {
  return (
    <li className="flex items-center justify-between py-1.5">
      <span className="font-mono text-[11px] text-secondary">{label}</span>
      <span
        className={`font-mono text-xs tabular-nums ${
          warn ? "text-sev-high" : "text-primary"
        }`}
      >
        {value}
      </span>
    </li>
  );
}

const SHOWN_COUNTERS: [string, string][] = [
  ["lines", "log lines read"],
  ["scored_requests", "requests scored"],
  ["payload_anomalies", "payload anomalies"],
  ["recon_anomalies", "scan anomalies"],
  ["cases_escalated", "cases escalated"],
];
const WARN_COUNTERS: [string, string][] = [
  ["sensor_errors", "sensor errors"],
  ["handler_errors", "feed errors"],
  ["events_rejected", "events rejected"],
];

export function PipelinePanel({ pipeline }: { pipeline: PipelineTelemetry }) {
  const { ingestion, dispatcher, sensors } = pipeline;
  const lag = ingestion?.seconds_since_last_scored_line ?? null;

  return (
    <div className="grid gap-4 sm:grid-cols-2">
      <div>
        <p className="mb-1 font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
          Log ingestion
        </p>
        {ingestion === null ? (
          <p className="text-xs leading-relaxed text-secondary">
            Ingestion is off on this server. It starts with the real
            deployment.
          </p>
        ) : (
          <ul className="flex flex-col divide-y divide-hairline">
            <Row
              label="feed"
              value={ingestion.running ? "running" : "stopped"}
              warn={!ingestion.running}
            />
            <Row
              label="mode"
              value={ingestion.log_only ? "log only" : "live alerts"}
            />
            <Row
              label="last scored line"
              value={lag === null ? "none yet" : `${lag.toFixed(0)} s ago`}
            />
            <Row label="open windows" value={ingestion.open_windows} />
            {SHOWN_COUNTERS.map(([key, label]) => (
              <Row key={key} label={label} value={ingestion.counters[key] ?? 0} />
            ))}
            {WARN_COUNTERS.filter(([key]) => (ingestion.counters[key] ?? 0) > 0).map(
              ([key, label]) => (
                <Row key={key} label={label} value={ingestion.counters[key]} warn />
              )
            )}
          </ul>
        )}
      </div>

      <div>
        <p className="mb-1 font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
          Correlator and agent
        </p>
        <ul className="flex flex-col divide-y divide-hairline">
          <Row
            label="sensors loaded"
            value={`${sensors.loaded}${sensors.failed ? ` (${sensors.failed} failed)` : ""}`}
            warn={!sensors.complete}
          />
          <Row label="correlator windows" value={pipeline.correlator_windows} />
          {dispatcher && (
            <>
              <Row
                label="agent runs now"
                value={`${dispatcher.running} / ${dispatcher.max_concurrent}`}
              />
              <Row
                label="agent runs, last hour"
                value={`${dispatcher.runs_last_hour} / ${dispatcher.hourly_cap}`}
                warn={dispatcher.runs_last_hour >= dispatcher.hourly_cap}
              />
            </>
          )}
        </ul>
      </div>
    </div>
  );
}
