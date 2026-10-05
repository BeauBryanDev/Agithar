// Console slice — the chat thread, its session id and the streaming state.

import { create } from "zustand";
import type { AnalysisMessage, EvidenceRef } from "../types/analysis";

interface AnalysisState {
  messages: AnalysisMessage[];
  streaming: boolean;
  sessionId: string | null; // the server-side chat session
  statusLine: string | null; // what Agithar is doing right now
  activeEvidenceId: string | null; // for the evidence connector highlight
  addMessage: (msg: AnalysisMessage) => void;
  updateStreamingContent: (id: string, content: string) => void;
  finalizeStreaming: (id: string, refs: EvidenceRef[]) => void;
  setStreaming: (v: boolean) => void;
  setSessionId: (id: string | null) => void;
  setStatusLine: (text: string | null) => void;
  setActiveEvidence: (id: string | null) => void;
  reset: () => void;
}

export const useAnalysisStore = create<AnalysisState>((set) => ({
  messages: [],
  streaming: false,
  sessionId: null,
  statusLine: null,
  activeEvidenceId: null,
  addMessage: (msg) => set((s) => ({ messages: [...s.messages, msg] })),
  updateStreamingContent: (id, content) =>
    set((s) => ({
      messages: s.messages.map((m) =>
        m.id === id ? { ...m, content } : m
      ),
    })),
  finalizeStreaming: (id, refs) =>
    set((s) => ({
      messages: s.messages.map((m) =>
        m.id === id ? { ...m, streaming: false, evidence_refs: refs } : m
      ),
    })),
  setStreaming: (v) => set({ streaming: v }),
  setSessionId: (sessionId) => set({ sessionId }),
  setStatusLine: (statusLine) => set({ statusLine }),
  setActiveEvidence: (id) => set({ activeEvidenceId: id }),
  reset: () =>
    set({
      messages: [],
      streaming: false,
      sessionId: null,
      statusLine: null,
      activeEvidenceId: null,
    }),
}));
