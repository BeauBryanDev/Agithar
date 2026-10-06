import type { LiveEvent } from "../../types/live";
import { detectorLabel } from "../../utils/detectors";
import { scoreToSeverity, severityTextClass } from "../../utils/severity";

function clock(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString("en-GB", { hour12: false });
}

function statusTone(status: number): string {
  if (status >= 500) return "text-sev-critical";
  if (status >= 400) return "text-sev-high";
  return "text-secondary";
}

export function LiveEventFeed({ events }: { events: LiveEvent[] }) {
  if (events.length === 0) {
    return (
      <p className="p-4 text-xs leading-relaxed text-secondary">
        No anomalies seen yet. Events from the log feed appear here as soon as
        a sensor flags a request or a scan window.
      </p>
    );
  }

  return (
    <div className="max-h-96 overflow-y-auto">
      <table className="w-full border-collapse font-mono text-[11px]">
        <thead className="sticky top-0 bg-panel text-left text-dim">
          <tr>
            <th className="px-3 py-1.5 font-normal">time</th>
            <th className="px-2 py-1.5 font-normal">sensor</th>
            <th className="px-2 py-1.5 font-normal">score</th>
            <th className="px-2 py-1.5 font-normal">source</th>
            <th className="px-2 py-1.5 font-normal">st</th>
            <th className="px-2 py-1.5 font-normal">path</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr
              key={`${e.timestamp}-${e.ip}-${i}`}
              className="border-t border-hairline"
            >
              <td className="whitespace-nowrap px-3 py-1.5 text-secondary">
                {clock(e.timestamp)}
              </td>
              <td className="whitespace-nowrap px-2 py-1.5 text-primary">
                {detectorLabel(e.sensor)}
              </td>
              <td
                className={`px-2 py-1.5 tabular-nums ${severityTextClass(
                  scoreToSeverity(e.score)
                )}`}
              >
                {e.score.toFixed(2)}
              </td>
              <td className="whitespace-nowrap px-2 py-1.5 text-electric">
                {e.ip}
              </td>
              <td className={`px-2 py-1.5 tabular-nums ${statusTone(e.status)}`}>
                {e.status}
              </td>
              <td
                className="max-w-[16rem] truncate px-2 py-1.5 text-secondary"
                title={`${e.host} ${e.path}`}
              >
                {e.path || "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
