// Friendly names for the backend sensor ids.

import type { DetectorName } from "../types/detector";

const LABELS: Record<DetectorName, string> = {
  log_sentinel: "LogSentinel",
  net_guard: "NetGuard",
  http_payload_sensor: "HTTP Payload Sensor",
  netflow_sensor: "Netflow Sensor",
  recon_sensor: "Recon Sensor",
};

export function detectorLabel(name: string): string {
  return LABELS[name as DetectorName] ?? name;
}

export function isLogDetector(name: DetectorName): boolean {
  return name === "log_sentinel";
}
