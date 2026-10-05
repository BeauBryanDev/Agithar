import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import type { TimelinePoint } from "../../types/dashboard";
import { formatTime } from "../../utils/formatters";

interface AnomalyTimelineProps {
  data: TimelinePoint[];
  daily: boolean; // one point per day instead of per hour
}

export function AnomalyTimeline({ data, daily }: AnomalyTimelineProps) {
  const chartData = data.map((d) => ({
    time: daily
      ? new Date(d.timestamp).toLocaleDateString("en-CA")
      : formatTime(d.timestamp),
    score: Number(d.score.toFixed(2)),
    incidents: d.incidents,
  }));

  return (
    <div className="h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={chartData} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <CartesianGrid stroke="var(--color-hairline)" strokeDasharray="2 4" vertical={false} />
          <XAxis
            dataKey="time"
            tick={{ fill: "var(--color-dim)", fontSize: 10, fontFamily: "var(--font-mono)" }}
            stroke="var(--color-hairline)"
            interval="preserveStartEnd"
          />
          <YAxis
            domain={[0, 1]}
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
          />
          <Line
            type="monotone"
            dataKey="score"
            stroke="var(--color-electric)"
            strokeWidth={1.75}
            dot={false}
            activeDot={{ r: 3, fill: "var(--color-neon)" }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
