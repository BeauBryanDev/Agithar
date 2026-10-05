// GET /dashboard and GET /detectors. All dashboard network I/O lives here.

import { apiClient } from "./apiClient";
import type { DashboardData, DetectorsResponse } from "../types/dashboard";

export async function fetchDashboard(hours: number): Promise<DashboardData> {
  const { data } = await apiClient.get<DashboardData>("/dashboard", {
    params: { hours },
  });
  return data;
}

export async function fetchDetectors(): Promise<DetectorsResponse> {
  const { data } = await apiClient.get<DetectorsResponse>("/detectors");
  return data;
}
