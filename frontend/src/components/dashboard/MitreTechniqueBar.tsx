import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface MitreTechniqueBarProps {
  data: { technique: string; count: number }[];
}

export function MitreTechniqueBar({ data }: MitreTechniqueBarProps) {
  return (
    <div className="h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="vertical"
          margin={{ top: 4, right: 16, left: 8, bottom: 4 }}
        >
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="technique"
            width={130}
            tick={{ fill: "var(--color-secondary)", fontSize: 10, fontFamily: "var(--font-mono)" }}
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
          <Bar
            dataKey="count"
            fill="var(--color-electric)"
            fillOpacity={0.7}
            radius={[0, 2, 2, 0]}
            barSize={14}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
