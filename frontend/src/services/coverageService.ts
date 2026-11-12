// GET /coverage and the ATT&CK Navigator layer download.

import { apiClient } from "./apiClient";
import type { CoverageData } from "../types/coverage";

const LAYER_FILENAME = "agithar_coverage_layer.json";

export async function fetchCoverage(): Promise<CoverageData> {
  const { data } = await apiClient.get<CoverageData>("/coverage", {
    timeout: 15_000,
  });
  return data;
}

/** Fetch the layer with the session token and hand it to the browser. */
export async function downloadNavigatorLayer(): Promise<void> {
  const { data } = await apiClient.get<Blob>("/coverage/navigator", {
    responseType: "blob",
    timeout: 15_000,
  });
  const url = URL.createObjectURL(data);
  const link = document.createElement("a");
  link.href = url;
  link.download = LAYER_FILENAME;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
