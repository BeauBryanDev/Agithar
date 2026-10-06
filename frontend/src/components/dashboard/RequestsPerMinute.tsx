import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { MinutePoint } from "../../types/live";

export function RequestsPerMinute({ data }: { data: MinutePoint[] }) {
  const rows = data.map((d) => ({
    time: new Date(d.minute * 1000).toLocaleTimeString("en-GB", {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }),
    requests: d.requests,
    anomalies: d.anomalies,
  }));

  return (
    <div className="h-44 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <CartesianGrid stroke="var(--color-hairline)" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="time"
            tick={{ fill: "var(--color-dim)", fontSize: 10, fontFamily: "var(--font-mono)" }}
            stroke="var(--color-hairline)"
            interval="preserveStartEnd"
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: "var(--color-dim)", fontSize: 10, fontFamily: "var(--font-mono)" }}
            stroke="var(--color-hairline)"
          />
          <Tooltip
            contentStyle={{
              background: "var(--color-panel-2)",
              border: "1px solid var(--color-hairline)",
              borderRadius: 2,
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              color: "var(--color-primary)",
            }}
            cursor={{ fill: "var(--color-panel-2)" }}
          />
          <Bar dataKey="requests" fill="var(--color-electric)" />
          <Bar dataKey="anomalies" fill="var(--color-sev-critical)" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
