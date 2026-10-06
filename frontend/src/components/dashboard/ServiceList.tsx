interface ServiceListProps {
  title: string;
  states: Record<string, string>;
}

const DOT: Record<string, string> = {
  active: "bg-sev-low",
  activating: "bg-sev-medium",
  reloading: "bg-sev-medium",
  deactivating: "bg-sev-medium",
  inactive: "bg-sev-high",
  failed: "bg-sev-critical",
};

export function ServiceList({ title, states }: ServiceListProps) {
  const entries = Object.entries(states);
  if (entries.length === 0) return null;
  return (
    <div>
      <p className="mb-1 font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
        {title}
      </p>
      <ul className="flex flex-col divide-y divide-hairline">
        {entries.map(([name, state]) => (
          <li key={name} className="flex items-center justify-between py-1.5">
            <span className="flex items-center gap-2 font-mono text-xs text-primary">
              <span
                className={`h-2 w-2 rounded-full ${DOT[state] ?? "bg-dim"}`}
              />
              {name}
            </span>
            <span className="font-mono text-[11px] text-secondary">{state}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
