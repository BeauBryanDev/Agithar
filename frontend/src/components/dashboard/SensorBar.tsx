import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import type { SensorCount } from "../../types/dashboard";
import { detectorLabel } from "../../utils/detectors";

interface SensorBarProps {
  data: SensorCount[];
}

export function SensorBar({ data }: SensorBarProps) {
  const chartData = data.map((d) => ({
    name: detectorLabel(d.sensor),
    value: d.count,
  }));

  return (
    <div className="h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={chartData}
          layout="vertical"
          margin={{ top: 4, right: 16, left: 8, bottom: 4 }}
        >
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="name"
            width={130}
            tick={{ fill: "var(--color-secondary)", fontSize: 11, fontFamily: "var(--font-mono)" }}
            stroke="var(--color-hairline)"
          />
          <Tooltip
            cursor={{ fill: "var(--color-panel-2)" }}
            contentStyle={{
              background: "var(--color-panel-2)",
              border: "1px solid var(--color-hairline)",
              borderRadius: 2,
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              color: "var(--color-primary)",
            }}
          />
          <Bar dataKey="value" radius={[0, 2, 2, 0]} barSize={14}>
            {chartData.map((d, i) => (
              <Cell
                key={d.name}
                fill={i === 0 ? "var(--color-neon)" : "var(--color-electric)"}
                fillOpacity={i === 0 ? 1 : 0.55}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
