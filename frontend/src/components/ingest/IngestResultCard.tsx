import { Badge } from "../common/Badge";
import { ScoreReadout } from "../common/ScoreReadout";
import type { IngestResult } from "../../types/ingest";
import { detectorLabel } from "../../utils/detectors";
import { formatBytes, formatScore } from "../../utils/formatters";
import { scoreToSeverity, severityTextClass } from "../../utils/severity";

function stamp(epoch: number | null): string {
  return epoch === null
    ? "-"
    : new Date(epoch * 1000).toLocaleString("en-GB", { hour12: false });
}

function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-dim">{label}</p>
      <p className="font-mono text-lg font-semibold tabular-nums text-electric">{value}</p>
    </div>
  );
}

/** What the sensors found in one uploaded file. Every string is shown as
 *  plain text by React; nothing here is rendered as HTML. */
export function IngestResultCard({ result: r }: { result: IngestResult }) {
  const flaggedSources = r.sources.length;

  return (
    <div className="mt-3 border-t border-hairline pt-4">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-primary">{r.kind_label}</p>
          <p className="font-mono text-[11px] text-dim">
            {formatBytes(r.size_bytes)} · analysed in {(r.duration_ms / 1000).toFixed(1)} s
            {r.time_first !== null && ` · ${stamp(r.time_first)} to ${stamp(r.time_last)}`}
          </p>
        </div>
        <div className="flex items-center gap-4">
          <Badge level={r.severity} label={`${r.severity} overall`} />
          <ScoreReadout label="top composite" value={formatScore(r.composite_score)} size="md" />
        </div>
      </div>

      {r.truncated && (
        <p className="mt-3 font-mono text-[11px] text-sev-medium">
          Only part of the file was analysed: {r.truncated_reason}.
        </p>
      )}

      <div className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Kpi label="read" value={r.items_read.toLocaleString()} />
        <Kpi label="unreadable" value={r.items_unreadable.toLocaleString()} />
        <Kpi label="suspicious sources" value={String(flaggedSources)} />
        <Kpi label="findings" value={String(r.findings.length)} />
      </div>

      {Object.keys(r.breakdown).length > 0 && (
        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-secondary">
          {Object.entries(r.breakdown).map(([k, v]) => (
            <span key={k}>
              {k} · {v.toLocaleString()}
            </span>
          ))}
        </div>
      )}

      <p className="mb-1 mt-5 font-mono text-[10px] uppercase tracking-[0.2em] text-dim">sensors</p>
      <table className="w-full border-collapse font-mono text-[11px]">
        <thead className="text-left text-dim">
          <tr>
            <th className="py-1 font-normal">sensor</th>
            <th className="py-1 font-normal">scored</th>
            <th className="py-1 font-normal">flagged</th>
            <th className="py-1 font-normal">max score</th>
          </tr>
        </thead>
        <tbody>
          {r.sensors.map((s) => (
            <tr key={s.sensor} className="border-t border-hairline">
              <td className="py-1 text-primary">{detectorLabel(s.sensor)}</td>
              <td className="py-1 tabular-nums text-secondary">{s.scored.toLocaleString()}</td>
              <td className={`py-1 tabular-nums ${s.flagged ? "text-sev-high" : "text-secondary"}`}>
                {s.flagged.toLocaleString()}
              </td>
              <td className="py-1 tabular-nums text-electric">{s.max_score.toFixed(3)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {r.sources.length > 0 && (
        <>
          <p className="mb-1 mt-5 font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
            suspicious sources
          </p>
          <div className="max-h-56 overflow-y-auto">
            <table className="w-full border-collapse font-mono text-[11px]">
              <thead className="sticky top-0 bg-panel-2 text-left text-dim">
                <tr>
                  <th className="px-2 py-1 font-normal">source</th>
                  <th className="px-2 py-1 font-normal">severity</th>
                  <th className="px-2 py-1 font-normal">score</th>
                  <th className="px-2 py-1 font-normal">sensors</th>
                  <th className="px-2 py-1 font-normal">flagged / items</th>
                </tr>
              </thead>
              <tbody>
                {r.sources.map((s) => (
                  <tr key={s.source} className="border-t border-hairline">
                    <td className="px-2 py-1 text-electric">{s.source}</td>
                    <td className="px-2 py-1"><Badge level={s.severity} /></td>
                    <td className="px-2 py-1 tabular-nums text-primary">{formatScore(s.composite_score)}</td>
                    <td className="px-2 py-1 text-secondary">{s.sensors.map(detectorLabel).join(", ")}</td>
                    <td className="px-2 py-1 tabular-nums text-secondary">
                      {s.flagged.toLocaleString()} / {s.items.toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {r.findings.length > 0 ? (
        <>
          <p className="mb-1 mt-5 font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
            top findings
          </p>
          <div className="max-h-72 overflow-y-auto">
            <table className="w-full border-collapse font-mono text-[11px]">
              <thead className="sticky top-0 bg-panel-2 text-left text-dim">
                <tr>
                  <th className="px-2 py-1 font-normal">sensor</th>
                  <th className="px-2 py-1 font-normal">score</th>
                  <th className="px-2 py-1 font-normal">source</th>
                  <th className="px-2 py-1 font-normal">what</th>
                  <th className="px-2 py-1 font-normal">st</th>
                  <th className="px-2 py-1 font-normal">x</th>
                </tr>
              </thead>
              <tbody>
                {r.findings.map((f, i) => (
                  <tr key={i} className="border-t border-hairline">
                    <td className="whitespace-nowrap px-2 py-1 text-primary">{detectorLabel(f.sensor)}</td>
                    <td className={`px-2 py-1 tabular-nums ${severityTextClass(scoreToSeverity(f.score))}`}>
                      {f.score.toFixed(2)}
                    </td>
                    <td className="whitespace-nowrap px-2 py-1 text-electric">{f.source ?? "-"}</td>
                    <td className="max-w-[18rem] truncate px-2 py-1 text-secondary" title={f.path ?? f.detail ?? ""}>
                      {f.path ?? f.detail ?? "-"}
                    </td>
                    <td className="px-2 py-1 tabular-nums text-secondary">{f.status ?? "-"}</td>
                    <td className="px-2 py-1 tabular-nums text-dim">{f.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <p className="mt-5 text-xs text-sev-low">Nothing suspicious found by the sensors.</p>
      )}

      <ul className="mt-5 list-disc space-y-1 pl-5 text-[11px] leading-relaxed text-dim">
        {r.notes.map((n) => (
          <li key={n}>{n}</li>
        ))}
      </ul>
    </div>
  );
}
