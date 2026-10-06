// GET /telemetry. Live numbers for the dashboard.

import { apiClient } from "./apiClient";
import type { Telemetry } from "../types/telemetry";

export async function fetchTelemetry(): Promise<Telemetry> {
  const { data } = await apiClient.get<Telemetry>("/telemetry", {
    timeout: 8_000,
  });
  return data;
}
