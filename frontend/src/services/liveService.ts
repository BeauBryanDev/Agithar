// GET /live. The newest anomalies and request rates from the log feed.

import { apiClient } from "./apiClient";
import type { LiveData } from "../types/live";

export async function fetchLive(limit = 100): Promise<LiveData> {
  const { data } = await apiClient.get<LiveData>("/live", {
    params: { limit },
    timeout: 8_000,
  });
  return data;
}
