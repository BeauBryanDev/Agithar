// GET /incidents: the detection feed. All feed network I/O lives here.

import { apiClient } from "./apiClient";
import type { DetectionRow, FeedList } from "../types/feed";

const FEED_LIMIT = 100;

export async function fetchFeed(): Promise<DetectionRow[]> {
  const { data } = await apiClient.get<FeedList>("/incidents", {
    params: { limit: FEED_LIMIT },
  });
  return data.items;
}
