// Console slice — the chat thread, its session id and the streaming state.

import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";
import { safeSessionStorage } from "./safeStorage";
import type { AnalysisMessage, EvidenceRef } from "../types/analysis";

// The last messages of the tab are kept across a reload.
const MAX_PERSISTED_MESSAGES = 100;
const STORAGE_KEY = "aegis.chat";

interface AnalysisState {
  messages: AnalysisMessage[];
  streaming: boolean;
  sessionId: string | null; // the server-side chat session
  statusLine: string | null; // what Agithar is doing right now
  activeEvidenceId: string | null; // for the evidence connector highlight
  remaining: number | null; // guest only: messages left in this time window
  setRemaining: (n: number | null) => void;
  addMessage: (msg: AnalysisMessage) => void;
  updateStreamingContent: (id: string, content: string) => void;
  finalizeStreaming: (id: string, refs: EvidenceRef[]) => void;
  setStreaming: (v: boolean) => void;
  setSessionId: (id: string | null) => void;
  setStatusLine: (text: string | null) => void;
  setActiveEvidence: (id: string | null) => void;
  reset: () => void;
}

export const useAnalysisStore = create<AnalysisState>()(
  persist(
    (set) => ({
      messages: [],
      streaming: false,
      sessionId: null,
      statusLine: null,
      activeEvidenceId: null,
      remaining: null,
      setRemaining: (remaining) => set({ remaining }),
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
    }),
    {
      name: STORAGE_KEY,
      storage: createJSONStorage(() => safeSessionStorage),
      // Only the thread and the server session id; never transient flags.
      partialize: (s) => ({
        messages: s.messages.slice(-MAX_PERSISTED_MESSAGES),
        sessionId: s.sessionId,
      }),
      // A reload during an answer leaves a half message: it is final now.
      merge: (persisted, current) => {
        const saved = persisted as
          | Pick<AnalysisState, "messages" | "sessionId">
          | undefined;
        if (!saved || !Array.isArray(saved.messages)) return current;
        return {
          ...current,
          sessionId:
            typeof saved.sessionId === "string" ? saved.sessionId : null,
          messages: saved.messages.map((m) => ({ ...m, streaming: false })),
        };
      },
    }
  )
);
