interface TopRow {
  label: string;
  count: number;
  hint?: string;
}

export function TopList({ rows, empty }: { rows: TopRow[]; empty: string }) {
  if (rows.length === 0) {
    return <p className="text-xs text-dim">{empty}</p>;
  }
  const max = Math.max(...rows.map((r) => r.count), 1);

  return (
    <ul className="flex flex-col gap-2">
      {rows.map((r) => (
        <li key={r.label}>
          <div className="flex items-baseline justify-between gap-3">
            <span
              className="min-w-0 truncate font-mono text-xs text-primary"
              title={r.label}
            >
              {r.label}
            </span>
            <span className="font-mono text-xs tabular-nums text-electric">
              {r.count}
            </span>
          </div>
          <div className="mt-1 h-1 w-full overflow-hidden rounded-full bg-void">
            <div
              className="h-full bg-electric"
              style={{ width: `${(r.count / max) * 100}%` }}
            />
          </div>
          {r.hint && (
            <span className="font-mono text-[10px] text-dim">{r.hint}</span>
          )}
        </li>
      ))}
    </ul>
  );
}
