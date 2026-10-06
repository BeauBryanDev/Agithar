import { apiClient } from "./apiClient";

export type HealthState = "ready" | "degraded" | "offline";

export interface Health {
  state: HealthState;
  sensors: boolean;
  database: boolean;
}

const OFFLINE: Health = { state: "offline", sensors: false, database: false };

/** The ready endpoint answers 503 with a body when degraded, so 503 is data. */
export async function fetchHealth(): Promise<Health> {
  try {
    const res = await apiClient.get("/health/ready", {
      timeout: 5_000,
      validateStatus: (s) => s === 200 || s === 503,
    });
    const body = res.data as { sensors?: unknown; database?: unknown };
    const sensors = body.sensors === true;
    const database = body.database === true;
    return {
      state: sensors && database ? "ready" : "degraded",
      sensors,
      database,
    };
  } catch {
    return OFFLINE;
  }
}
