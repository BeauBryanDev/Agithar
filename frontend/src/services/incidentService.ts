// GET /incidents: the detection feed. All feed network I/O lives here.

import { apiClient } from "./apiClient";
import type { DetectionRow, FeedList } from "../types/feed";
import type { IncidentDetail } from "../types/incident";

const FEED_LIMIT = 100;

export async function fetchFeed(): Promise<DetectionRow[]> {
  const { data } = await apiClient.get<FeedList>("/incidents", {
    params: { limit: FEED_LIMIT },
  });
  return data.items;
}

export async function fetchIncident(caseKey: string): Promise<IncidentDetail> {
  const { data } = await apiClient.get<IncidentDetail>(
    `/incidents/${encodeURIComponent(caseKey)}`
  );
  return data;
}
