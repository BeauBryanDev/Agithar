// Detector outputs slice — evidence cards for the console right column.

import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";
import { safeSessionStorage } from "./safeStorage";
import type { DetectorResult } from "../types/detector";

interface DetectorState {
  evidence: DetectorResult[];
  expanded: Record<string, boolean>; // card id -> raw JSON expanded
  setEvidence: (e: DetectorResult[]) => void;
  toggleExpanded: (id: string) => void;
  clear: () => void;
}

export const useDetectorStore = create<DetectorState>()(
  persist(
    (set) => ({
      evidence: [],
      expanded: {},
      setEvidence: (e) => set({ evidence: e }),
      toggleExpanded: (id) =>
        set((s) => ({ expanded: { ...s.expanded, [id]: !s.expanded[id] } })),
      clear: () => set({ evidence: [], expanded: {} }),
    }),
    {
      name: "aegis.evidence",
      storage: createJSONStorage(() => safeSessionStorage),
      partialize: (s) => ({ evidence: s.evidence, expanded: s.expanded }),
    }
  )
);
