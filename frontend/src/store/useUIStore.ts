// UI state slice — sidebar collapsed, detectors-active indicator.

import { create } from "zustand";

interface UIState {
  sidebarCollapsed: boolean;
  detectorsActive: boolean;
  toggleSidebar: () => void;
  setSidebarCollapsed: (v: boolean) => void;
  setDetectorsActive: (v: boolean) => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarCollapsed: false,
  detectorsActive: false,
  toggleSidebar: () =>
    set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
  setSidebarCollapsed: (v) => set({ sidebarCollapsed: v }),
  setDetectorsActive: (v) => set({ detectorsActive: v }),
}));
