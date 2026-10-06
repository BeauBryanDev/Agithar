import { Panel } from "../common/Panel";
import type { IncidentDetail } from "../../types/incident";
import { detectorLabel } from "../../utils/detectors";
import { formatScore } from "../../utils/formatters";
import { scoreToSeverity, severityBgClass } from "../../utils/severity";

export function SensorScores({ incident }: { incident: IncidentDetail }) {
  const rows = Object.entries(incident.sensor_scores).sort((a, b) => b[1] - a[1]);

  return (
    <Panel title="Sensor scores" bodyClassName="p-4">
      <p className="mb-3 font-mono text-[11px] text-secondary">
        {incident.num_sensors} sensor{incident.num_sensors === 1 ? "" : "s"} ·{" "}
        {incident.num_strong_sensors} strong · composite{" "}
        <span className="text-electric">{formatScore(incident.composite_score)}</span>
      </p>
      <ul className="flex flex-col gap-3">
        {rows.map(([sensor, score]) => (
          <li key={sensor}>
            <div className="flex items-baseline justify-between">
              <span className="font-mono text-xs text-primary">
                {detectorLabel(sensor)}
              </span>
              <span className="font-mono text-xs tabular-nums text-electric">
                {formatScore(score)}
                <span className="ml-2 text-dim">
                  x{incident.event_counts[sensor] ?? 1}
                </span>
              </span>
            </div>
            <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-void">
              <div
                className={`h-full ${severityBgClass(scoreToSeverity(score))}`}
                style={{ width: `${Math.min(score, 1) * 100}%` }}
              />
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
