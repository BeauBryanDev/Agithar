import { ShieldAlert } from "lucide-react";
import { Panel } from "../components/common/Panel";
import { EmptyState } from "../components/common/EmptyState";
import { SensorCard } from "../components/sensors/SensorCard";
import { useSensors } from "../hooks/useSensors";

export function SensorsPage() {
  const { data, error } = useSensors();

  if (!data) {
    return error ? (
      <EmptyState
        icon={<ShieldAlert className="h-8 w-8" strokeWidth={1.5} />}
        title="Could not load the sensors"
        hint={error}
      />
    ) : (
      <div className="p-4 font-mono text-xs text-dim">Probing the sensors…</div>
    );
  }

  const healthy = data.sensors.filter((s) => s.status === "ok").length;

  return (
    <div className="p-4">
      <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-primary">Sensors</h1>
          <p className="max-w-2xl text-xs text-secondary">
            The five detectors Agithar reads. Each one is probed with a
            harmless sample through its real model; a pass shows the model
            runs, not that it is accurate.
          </p>
        </div>
        <div className="flex items-center gap-4 font-mono text-xs">
          <span className={data.all_healthy ? "text-sev-low" : "text-sev-high"}>
            {healthy} of {data.sensors.length} healthy
          </span>
          <span className={data.feed_running ? "text-sev-low" : "text-dim"}>
            log feed {data.feed_running ? "running" : "off"}
          </span>
        </div>
      </div>

      {error && (
        <p className="mb-3 font-mono text-[11px] text-sev-high">
          Showing the last result: {error}
        </p>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        {data.sensors.map((s) => (
          <SensorCard key={s.name} sensor={s} />
        ))}
      </div>

      <div className="mt-4">
        <Panel title="How a case is raised" bodyClassName="p-4">
          <p className="text-xs leading-relaxed text-secondary">
            {data.how_cases_are_raised}
          </p>
        </Panel>
      </div>
    </div>
  );
}
