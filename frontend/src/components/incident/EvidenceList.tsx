import { Panel } from "../common/Panel";
import type { EvidenceEntry } from "../../types/incident";
import { detectorLabel } from "../../utils/detectors";
import { formatJSON } from "../../utils/formatters";

function text(value: unknown): string | null {
  return typeof value === "string" || typeof value === "number"
    ? String(value)
    : null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function EvidenceList({ evidence }: { evidence: EvidenceEntry[] }) {
  return (
    <Panel title={`Evidence · ${evidence.length} sensor event${evidence.length === 1 ? "" : "s"}`} bodyClassName="p-4">
      {evidence.length === 0 ? (
        <p className="text-xs text-dim">No evidence stored.</p>
      ) : (
        <ul className="flex flex-col gap-4">
          {evidence.map((e, i) => {
            const sensor = text(e.source_sensor) ?? "unknown";
            const score = typeof e.score === "number" ? e.score : null;
            const context = asRecord(e.context);
            const detail = asRecord(e.detail);

            return (
              <li
                key={`${sensor}-${i}`}
                className="hud-corners border border-hairline bg-panel-2 p-3"
              >
                <div className="flex items-baseline justify-between gap-3">
                  <span className="font-mono text-xs text-primary">
                    {detectorLabel(sensor)}
                  </span>
                  <span className="font-mono text-xs tabular-nums text-electric">
                    {score === null ? "-" : score.toFixed(3)}
                  </span>
                </div>

                {context && (
                  <dl className="mt-2 grid grid-cols-[5.5rem_1fr] gap-x-3 gap-y-1 font-mono text-[11px]">
                    {(["method", "host", "path", "status"] as const).map((k) =>
                      text(context[k]) ? (
                        <div key={k} className="contents">
                          <dt className="text-dim">{k}</dt>
                          <dd className="break-all text-secondary">
                            {text(context[k])}
                          </dd>
                        </div>
                      ) : null
                    )}
                    {text(context.user_agent_sha256) && (
                      <div className="contents">
                        <dt className="text-dim">user agent</dt>
                        <dd className="break-all text-dim">
                          sha256 {text(context.user_agent_sha256)?.slice(0, 16)}…
                        </dd>
                      </div>
                    )}
                  </dl>
                )}

                {detail && Object.keys(detail).length > 0 && (
                  <details className="mt-2">
                    <summary className="cursor-pointer font-mono text-[10px] uppercase tracking-wider text-dim hover:text-secondary">
                      sensor detail
                    </summary>
                    <pre className="mt-1 max-h-48 overflow-auto font-mono text-[11px] text-secondary">
                      {formatJSON(detail)}
                    </pre>
                  </details>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
