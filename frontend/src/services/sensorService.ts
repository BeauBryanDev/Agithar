// GET /sensors. Health probes, profiles and feed activity of the sensors.

import { apiClient } from "./apiClient";
import type { SensorsData } from "../types/sensors";

export async function fetchSensors(): Promise<SensorsData> {
  const { data } = await apiClient.get<SensorsData>("/sensors", {
    timeout: 15_000,
  });
  return data;
}
