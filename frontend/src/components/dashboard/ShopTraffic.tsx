import { useState } from "react";
import { Panel } from "../common/Panel";
import { ShopTrafficCard } from "./ShopTrafficCard";
import { useTraffic } from "../../hooks/useTraffic";
import type { RecentError } from "../../types/traffic";

const WINDOWS = [
  { label: "15 min", minutes: 15 },
  { label: "1 h", minutes: 60 },
  { label: "6 h", minutes: 360 },
  { label: "24 h", minutes: 1440 },
];

function clock(iso: string | null): string {
  return iso ? new Date(iso).toLocaleTimeString("en-GB", { hour12: false }) : "-";
}

function statusTone(status: number): string {
  return status >= 500 ? "text-sev-critical" : "text-sev-high";
}

function ErrorTable({ rows }: { rows: RecentError[] }) {
  if (rows.length === 0) {
    return <p className="p-4 text-xs text-dim">No errors in this window.</p>;
  }
  return (
    <div className="max-h-64 overflow-y-auto">
      <table className="w-full border-collapse font-mono text-[11px]">
        <thead className="sticky top-0 bg-panel text-left text-dim">
          <tr>
            <th className="px-3 py-1.5 font-normal">time</th>
            <th className="px-2 py-1.5 font-normal">shop</th>
            <th className="px-2 py-1.5 font-normal">st</th>
            <th className="px-2 py-1.5 font-normal">client</th>
            <th className="px-2 py-1.5 font-normal">type</th>
            <th className="px-2 py-1.5 font-normal">path</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((e, i) => (
            <tr key={`${e.time}-${e.ip}-${i}`} className="border-t border-hairline">
              <td className="whitespace-nowrap px-3 py-1.5 text-secondary">{clock(e.time)}</td>
              <td className="px-2 py-1.5 text-primary">{e.shop}</td>
              <td className={`px-2 py-1.5 tabular-nums ${statusTone(e.status)}`}>{e.status}</td>
              <td className="whitespace-nowrap px-2 py-1.5 text-electric">{e.ip}</td>
              <td className="px-2 py-1.5 text-secondary">{e.client_type}</td>
              <td className="max-w-[18rem] truncate px-2 py-1.5 text-secondary" title={e.path}>
                {e.path}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Traffic of each protected shop, read from the web server log. */
export function ShopTraffic() {
  const [minutes, setMinutes] = useState(60);
  const { data, error } = useTraffic(minutes);

  const selector = (
    <div className="flex items-center gap-1">
      {WINDOWS.map((w) => (
        <button
          key={w.minutes}
          onClick={() => setMinutes(w.minutes)}
          className={`rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider transition-colors ${
            minutes === w.minutes
              ? "border-electric bg-panel-2 text-electric"
              : "border-hairline text-secondary hover:text-primary"
          }`}
        >
          {w.label}
        </button>
      ))}
    </div>
  );

  return (
    <div className="mb-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="font-mono text-xs uppercase tracking-[0.18em] text-secondary">
          Shop traffic
        </h2>
        {selector}
      </div>

      {!data ? (
        <p className="font-mono text-xs text-dim">
          {error ? `Traffic unavailable: ${error}` : "Reading the web server log…"}
        </p>
      ) : !data.available ? (
        <Panel bodyClassName="p-4">
          <p className="text-xs leading-relaxed text-secondary">
            {data.note ?? "Traffic is not available."} It appears once the log
            is readable, on the real server.
          </p>
        </Panel>
      ) : (
        <>
          {(!data.window_complete || data.older_lines_not_read) && (
            <p className="mb-3 font-mono text-[11px] text-sev-medium">
              The log only goes back to{" "}
              {data.data_starts_at
                ? new Date(data.data_starts_at).toLocaleString("en-GB", { hour12: false })
                : "an unknown time"}
              {data.older_lines_not_read
                ? " (older lines were not read: size cap)"
                : ""}
              , so numbers cover less than the full window.
            </p>
          )}
          <div className="grid gap-4 xl:grid-cols-2">
            {data.shops.map((s) => (
              <ShopTrafficCard key={s.name} shop={s} minutes={data.window_minutes} />
            ))}
          </div>
          <div className="mt-4">
            <Panel title="Recent errors · all shops">
              <ErrorTable rows={data.recent_errors} />
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}
