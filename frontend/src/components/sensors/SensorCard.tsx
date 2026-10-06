import { Panel } from "../common/Panel";
import type { SensorInfo } from "../../types/sensors";
import { detectorLabel } from "../../utils/detectors";
import { scoreToSeverity, severityTextClass } from "../../utils/severity";

const STATUS: Record<SensorInfo["status"], { label: string; dot: string; text: string }> = {
  ok: { label: "healthy", dot: "bg-sev-low", text: "text-sev-low" },
  error: { label: "probe failed", dot: "bg-sev-critical", text: "text-sev-critical" },
  bad_output: { label: "bad output", dot: "bg-sev-critical", text: "text-sev-critical" },
  failed_to_load: { label: "failed to load", dot: "bg-sev-critical", text: "text-sev-critical" },
  missing: { label: "missing", dot: "bg-sev-high", text: "text-sev-high" },
};

function ago(epoch: number | null): string {
  if (epoch === null) return "never";
  const s = Math.max(0, Math.round(Date.now() / 1000 - epoch));
  if (s < 90) return `${s} s ago`;
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  return `${Math.round(s / 3600)} h ago`;
}

function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-dim">{label}</p>
      <p className="font-mono text-base font-semibold tabular-nums text-electric">{value}</p>
    </div>
  );
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="font-mono text-[10px] uppercase tracking-[0.2em] text-dim">{label}</dt>
      <dd className="text-xs leading-relaxed text-secondary">{value}</dd>
    </>
  );
}

export function SensorCard({ sensor: s }: { sensor: SensorInfo }) {
  const st = STATUS[s.status] ?? STATUS.missing;
  const live = !s.fed_by.startsWith("nothing live");
  const a = s.activity;

  return (
    <Panel
      title={detectorLabel(s.name)}
      bodyClassName="p-4"
      actions={
        <span className={`flex items-center gap-2 font-mono text-[11px] uppercase tracking-wider ${st.text}`}>
          <span className={`h-2 w-2 rounded-full ${st.dot}`} />
          {st.label}
        </span>
      }
    >
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span
          className={`rounded-sm border border-hairline bg-panel-2 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
            live ? "text-sev-low" : "text-sev-medium"
          }`}
        >
          {live ? "live feed" : "no live feed"}
        </span>
        <span className="rounded-sm border border-hairline bg-panel-2 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-secondary">
          weight {s.correlator_weight.toFixed(1)}
          {s.counts_as_strong ? " · strong" : " · weak"}
        </span>
        {s.mitre && (
          <span className="rounded-sm border border-hairline bg-panel-2 px-2 py-0.5 font-mono text-[10px] text-electric">
            {s.mitre}
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Kpi label="threshold" value={s.threshold === null ? "none" : s.threshold.toFixed(3)} />
        <Kpi label="probe" value={s.latency_ms === null ? "-" : `${s.latency_ms} ms`} />
        <Kpi label="scored" value={a.scored === null ? "-" : a.scored.toLocaleString()} />
        <Kpi label="flagged 1 h" value={a.scored === null ? "-" : String(a.flagged_last_hour)} />
      </div>
      {s.error && (
        <p className="mt-2 font-mono text-[11px] text-sev-critical">error: {s.error}</p>
      )}

      <p className="mt-4 text-sm leading-relaxed text-primary">{s.purpose}</p>

      <dl className="mt-3 grid grid-cols-[6.5rem_1fr] gap-x-3 gap-y-2">
        <Fact label="model" value={s.model} />
        <Fact label="trained on" value={s.trained_on} />
        <Fact label="sees" value={s.sees} />
        <Fact label="fed by" value={s.fed_by} />
        <Fact label="score" value={s.score} />
      </dl>

      <details className="mt-3">
        <summary className="cursor-pointer font-mono text-[10px] uppercase tracking-wider text-dim hover:text-secondary">
          known limits ({s.limits.length})
        </summary>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-xs leading-relaxed text-secondary">
          {s.limits.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </details>

      <div className="mt-4 border-t border-hairline pt-3">
        <p className="mb-1 font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
          last flagged · {ago(a.last_flagged_at)}
        </p>
        {a.recent.length === 0 ? (
          <p className="text-xs text-dim">
            {live ? "Nothing flagged in the last hour." : "No events: nothing feeds this sensor yet."}
          </p>
        ) : (
          <table className="w-full border-collapse font-mono text-[11px]">
            <tbody>
              {a.recent.map((e, i) => (
                <tr key={`${e.timestamp}-${i}`} className="border-t border-hairline">
                  <td className="whitespace-nowrap py-1 pr-3 text-secondary">
                    {new Date(e.timestamp * 1000).toLocaleTimeString("en-GB", { hour12: false })}
                  </td>
                  <td className={`pr-3 tabular-nums ${severityTextClass(scoreToSeverity(e.score))}`}>
                    {e.score.toFixed(2)}
                  </td>
                  <td className="pr-3 text-electric">{e.ip}</td>
                  <td className="max-w-[12rem] truncate text-secondary" title={e.path}>{e.path || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Panel>
  );
}
