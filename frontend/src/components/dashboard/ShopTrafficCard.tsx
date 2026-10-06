import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Panel } from "../common/Panel";
import { TopList } from "./TopList";
import type { ShopTraffic } from "../../types/traffic";

const SHOP_TITLE: Record<string, string> = {
  maisonroast: "Maison Roast",
  florabelle: "Florabelle",
};

function pct(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

function Kpi({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <div>
      <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
        {label}
      </p>
      <p
        className={`font-mono text-xl font-semibold tabular-nums ${
          warn ? "text-sev-high" : "text-electric"
        }`}
      >
        {value}
      </p>
    </div>
  );
}

const AXIS = { fill: "var(--color-dim)", fontSize: 10, fontFamily: "var(--font-mono)" };

export function ShopTrafficCard({ shop, minutes }: { shop: ShopTraffic; minutes: number }) {
  const rows = shop.series.map((p) => ({
    time: new Date(p.time * 1000).toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }),
    requests: p.requests,
    errors: p.errors,
  }));
  const classes = Object.entries(shop.status_classes);

  return (
    <Panel
      title={SHOP_TITLE[shop.name] ?? shop.name}
      bodyClassName="p-4"
      actions={
        <span className="font-mono text-[10px] text-dim">{shop.host}</span>
      }
    >
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Kpi label="requests" value={shop.requests.toLocaleString()} />
        <Kpi label="per minute" value={shop.requests_per_minute.toFixed(1)} />
        <Kpi label="errors" value={pct(shop.error_rate)} warn={shop.error_rate >= 0.05} />
        <Kpi label="clients" value={String(shop.unique_clients)} />
      </div>

      <div className="mt-4 h-40 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={rows} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
            <CartesianGrid stroke="var(--color-hairline)" strokeDasharray="2 4" vertical={false} />
            <XAxis dataKey="time" tick={AXIS} stroke="var(--color-hairline)" interval="preserveStartEnd" />
            <YAxis allowDecimals={false} tick={AXIS} stroke="var(--color-hairline)" />
            <Tooltip
              contentStyle={{
                background: "var(--color-panel-2)",
                border: "1px solid var(--color-hairline)",
                borderRadius: 2,
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                color: "var(--color-primary)",
              }}
            />
            <Area type="monotone" dataKey="requests" stroke="var(--color-electric)" fill="var(--color-electric)" fillOpacity={0.15} strokeWidth={1.5} />
            <Area type="monotone" dataKey="errors" stroke="var(--color-sev-critical)" fill="var(--color-sev-critical)" fillOpacity={0.25} strokeWidth={1.5} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] uppercase tracking-wider text-secondary">
        {classes.map(([k, v]) => (
          <span key={k}>
            {k} · {v}
          </span>
        ))}
        <span>404 · {pct(shop.not_found_rate)}</span>
        {shop.peak_minute && (
          <span>peak · {shop.peak_minute.requests}/min</span>
        )}
      </div>

      <div className="mt-4 grid gap-5 sm:grid-cols-2">
        <div>
          <p className="mb-2 font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
            top paths ({minutes >= 60 ? `${minutes / 60} h` : `${minutes} min`})
          </p>
          <TopList
            empty="No requests in this window."
            rows={shop.top_paths.slice(0, 5).map((p) => ({ label: p.path, count: p.requests }))}
          />
        </div>
        <div>
          <p className="mb-2 font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
            top clients
          </p>
          <TopList
            empty="No clients yet."
            rows={shop.top_clients.slice(0, 5).map((c) => ({
              label: c.ip,
              count: c.requests,
              hint: c.errors > 0 ? `${c.errors} errors` : undefined,
            }))}
          />
        </div>
        <div>
          <p className="mb-2 font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
            client types
          </p>
          <TopList
            empty="No clients yet."
            rows={shop.client_types.slice(0, 5).map((t) => ({ label: t.type, count: t.requests }))}
          />
        </div>
        <div>
          <p className="mb-2 font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
            top error paths
          </p>
          <TopList
            empty="No errors. Good."
            rows={shop.top_error_paths.slice(0, 5).map((p) => ({ label: p.path, count: p.requests }))}
          />
        </div>
      </div>
    </Panel>
  );
}
