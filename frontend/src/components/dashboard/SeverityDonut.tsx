import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import type { SeverityLevel } from "../../types/vulnerability";
import { severityVar, SEVERITY_ORDER } from "../../utils/severity";

interface SeverityDonutProps {
  distribution: Record<SeverityLevel, number>;
}

export function SeverityDonut({ distribution }: SeverityDonutProps) {
  const data = SEVERITY_ORDER.map((level) => ({
    name: level,
    value: distribution[level] ?? 0,
  }));
  const total = data.reduce((s, d) => s + d.value, 0);

  return (
    <div className="relative h-56 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            cx="50%"
            cy="50%"
            innerRadius={58}
            outerRadius={82}
            paddingAngle={2}
            stroke="var(--color-void)"
            strokeWidth={2}
          >
            {data.map((d) => (
              <Cell key={d.name} fill={severityVar(d.name)} />
            ))}
          </Pie>
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
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-mono text-3xl font-semibold text-primary tabular-nums">
          {total}
        </span>
        <span className="font-mono text-[10px] uppercase tracking-widest text-dim">
          incidents
        </span>
      </div>
    </div>
  );
}
