// Detection feed slice — rows + filter state.

import { create } from "zustand";
import type { DetectionRow, FeedFilterState } from "../types/feed";
import type { SeverityLevel } from "../types/vulnerability";

interface FeedState {
  rows: DetectionRow[];
  filters: FeedFilterState;
  setRows: (rows: DetectionRow[]) => void;
  setSeverityFilter: (s: SeverityLevel | "all") => void;
  setSourceFilter: (src: string) => void;
}

export const useFeedStore = create<FeedState>((set) => ({
  rows: [],
  filters: { severity: "all", source: "" },
  setRows: (rows) => set({ rows }),
  setSeverityFilter: (severity) =>
    set((s) => ({ filters: { ...s.filters, severity } })),
  setSourceFilter: (source) =>
    set((s) => ({ filters: { ...s.filters, source } })),
}));
