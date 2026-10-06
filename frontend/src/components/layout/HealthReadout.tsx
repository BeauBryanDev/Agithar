import { Activity } from "lucide-react";
import { useHealth } from "../../hooks/useHealth";

export function HealthReadout() {
  const health = useHealth();

  let label = "checking";
  let color = "text-dim";
  let detail = "Waiting for the first health check";

  if (health) {
    detail = `sensors: ${health.sensors ? "ok" : "down"} · database: ${
      health.database ? "ok" : "down"
    }`;
    if (health.state === "ready") {
      label = "OK";
      color = "text-sev-low";
    } else if (health.state === "degraded") {
      label = health.database ? "DEGRADED" : "DB DOWN";
      color = "text-sev-high";
    } else {
      label = "OFFLINE";
      color = "text-sev-critical";
      detail = "The backend is not reachable";
    }
  }

  return (
    <div className="flex items-center gap-2" title={detail}>
      <Activity className="h-3.5 w-3.5 text-dim" strokeWidth={1.75} />
      <span className="font-mono text-xs text-secondary">
        health <span className={color}>{label}</span>
      </span>
    </div>
  );
}
