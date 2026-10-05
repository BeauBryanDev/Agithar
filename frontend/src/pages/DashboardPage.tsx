import { useEffect, useState } from "react";
import { Panel } from "../components/common/Panel";
import { ScoreReadout } from "../components/common/ScoreReadout";
import { SeverityDonut } from "../components/dashboard/SeverityDonut";
import { AnomalyTimeline } from "../components/dashboard/AnomalyTimeline";
import { SensorBar } from "../components/dashboard/SensorBar";
import { SensorStatus } from "../components/dashboard/SensorStatus";
import { MitreTechniqueBar } from "../components/dashboard/MitreTechniqueBar";
import { EmptyState } from "../components/common/EmptyState";
import { fetchDashboard, fetchDetectors } from "../services/dashboardService";
import type { DashboardData, DetectorInfo } from "../types/dashboard";
import type { SeverityLevel } from "../types/vulnerability";
import { formatScore } from "../utils/formatters";
import { SEVERITY_ORDER, severityBgClass } from "../utils/severity";
import { ShieldAlert } from "lucide-react";

const WINDOWS = [
  { label: "24 h", hours: 24 },
  { label: "7 d", hours: 168 },
  { label: "30 d", hours: 720 },
];
// The backend buckets by hour up to two days, by day beyond that.
const HOURLY_LIMIT = 48;

export function DashboardPage() {
  const [hours, setHours] = useState(24);
  const [data, setData] = useState<DashboardData | null>(null);
  const [detectors, setDetectors] = useState<DetectorInfo[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setError(null);
    fetchDashboard(hours)
      .then((d) => alive && setData(d))
      .catch((err) => {
        if (alive) setError(err instanceof Error ? err.message : "Dashboard failed");
      });
    return () => {
      alive = false;
    };
  }, [hours]);

  useEffect(() => {
    fetchDetectors()
      .then((r) => setDetectors(r.detectors))
      .catch(() => setDetectors([]));
  }, []);

  if (error) {
    return (
      <EmptyState
        icon={<ShieldAlert className="h-8 w-8" strokeWidth={1.5} />}
        title="Could not load the dashboard"
        hint={error}
      />
    );
  }

  if (!data) {
    return (
      <div className="p-4 font-mono text-xs text-dim">Loading dashboard…</div>
    );
  }

  const levels = SEVERITY_ORDER.filter(
    (level: SeverityLevel) => level in data.severity_distribution
  );
  const distribution = data.severity_distribution as Record<SeverityLevel, number>;

  return (
    <div className="p-4">
      <div className="mb-4 flex items-center justify-between">
        <p className="font-mono text-xs text-secondary">
          {data.total_incidents} incidents in the last{" "}
          {WINDOWS.find((w) => w.hours === hours)?.label ?? `${hours} h`}
          {data.truncated && " (showing the newest ones)"}
        </p>
        <div className="flex items-center gap-1">
          {WINDOWS.map((w) => (
            <button
              key={w.hours}
              onClick={() => setHours(w.hours)}
              className={`rounded-sm border px-2.5 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors ${
                hours === w.hours
                  ? "border-electric bg-panel-2 text-electric"
                  : "border-hairline text-secondary hover:text-primary"
              }`}
            >
              {w.label}
            </button>
          ))}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <Panel title="Incident Severity" bodyClassName="p-4">
          <SeverityDonut distribution={distribution} />
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1">
            {levels.map((level) => (
              <div key={level} className="flex items-center gap-1.5">
                <span
                  className={`h-2 w-2 rounded-full ${severityBgClass(level)}`}
                />
                <span className="font-mono text-[10px] uppercase tracking-wider text-secondary">
                  {level} · {distribution[level] ?? 0}
                </span>
              </div>
            ))}
          </div>
        </Panel>

        <Panel
          title="Verdict Confidence"
          bodyClassName="flex flex-col justify-center gap-4 p-6"
        >
          {data.avg_confidence === null ? (
            <p className="text-xs leading-relaxed text-secondary">
              No verdicts in this window yet. Confidence appears once the master
              agent has judged an incident.
            </p>
          ) : (
            <>
              <ScoreReadout
                label="mean confidence"
                value={formatScore(data.avg_confidence)}
                size="xl"
              />
              <p className="text-xs leading-relaxed text-secondary">
                Mean confidence of the master agent&apos;s verdicts in this
                window.
              </p>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-void">
                <div
                  className="h-full bg-electric"
                  style={{ width: `${data.avg_confidence * 100}%` }}
                />
              </div>
            </>
          )}
        </Panel>

        <Panel
          title="Incident Score Timeline"
          bodyClassName="p-4"
          className="md:col-span-2 xl:col-span-1"
        >
          <AnomalyTimeline data={data.timeline} daily={hours > HOURLY_LIMIT} />
        </Panel>

        <Panel title="Incidents by Sensor" bodyClassName="p-4">
          {data.by_sensor.length === 0 ? (
            <p className="text-xs text-dim">No incidents in this window.</p>
          ) : (
            <SensorBar data={data.by_sensor} />
          )}
        </Panel>

        <Panel title="Sensors" bodyClassName="p-4">
          <SensorStatus detectors={detectors} />
        </Panel>

        <Panel title="Top MITRE ATT&CK Techniques" bodyClassName="p-4">
          {data.top_techniques.length === 0 ? (
            <p className="text-xs text-dim">
              No technique assigned yet: the master agent sets it with its
              verdict.
            </p>
          ) : (
            <MitreTechniqueBar
              data={data.top_techniques.map((t) => ({
                technique: t.name ? `${t.technique} ${t.name}` : t.technique,
                count: t.count,
              }))}
            />
          )}
        </Panel>
      </div>
    </div>
  );
}
