// CVE lookup. All CVE network I/O lives here.

import { apiClient, apiPath } from "./apiClient";
import type { VulnSearchResult } from "../types/vulnerability";

export async function searchVulnerabilities(
  query: string
): Promise<VulnSearchResult> {
  const { data } = await apiClient.get<VulnSearchResult>(apiPath("/vuln/search"), {
    params: { q: query },
  });
  return data;
}
