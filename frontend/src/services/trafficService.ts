// GET /traffic. Per-shop traffic from the web server log.

import { apiClient } from "./apiClient";
import type { TrafficData } from "../types/traffic";

export async function fetchTraffic(minutes: number): Promise<TrafficData> {
  const { data } = await apiClient.get<TrafficData>("/traffic", {
    params: { minutes },
    timeout: 15_000,
  });
  return data;
}
