// The signed-in user's past conversations: list, reopen, delete.

import { useCallback, useEffect, useState } from "react";
import {
  deleteSession,
  fetchSession,
  listSessions,
} from "../services/chatHistoryService";
import { useAnalysisStore } from "../store/useAnalysisStore";
import { useDetectorStore } from "../store/useDetectorStore";
import type { AnalysisMessage } from "../types/analysis";
import type { ChatMessage, ChatSessionSummary } from "../types/chat";

function toThread(messages: ChatMessage[]): AnalysisMessage[] {
  return messages.map((m) => ({
    id: m.id,
    role: m.role,
    content: m.content,
    evidence_refs: m.evidence_refs,
    created_at: m.created_at,
    streaming: false,
  }));
}

function describeError(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

export function useChatHistory(open: boolean) {
  const [items, setItems] = useState<ChatSessionSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const currentId = useAnalysisStore((s) => s.sessionId);
  const loadSession = useAnalysisStore((s) => s.loadSession);
  const resetThread = useAnalysisStore((s) => s.reset);
  const setEvidence = useDetectorStore((s) => s.setEvidence);
  const clearEvidence = useDetectorStore((s) => s.clear);

  const loadPage = useCallback(async (skip: number) => {
    setLoading(true);
    setError(null);
    try {
      const page = await listSessions(skip);
      setItems((prev) => (skip === 0 ? page.items : [...prev, ...page.items]));
      setTotal(page.total);
    } catch (err) {
      setError(describeError(err, "Could not load your conversations"));
    } finally {
      setLoading(false);
    }
  }, []);

  // Refreshed each time the list is opened, so a new chat shows up.
  useEffect(() => {
    if (open) void loadPage(0);
  }, [open, loadPage]);

  const reopen = useCallback(
    async (id: string): Promise<boolean> => {
      setBusyId(id);
      setError(null);
      try {
        const session = await fetchSession(id);
        clearEvidence();
        setEvidence(session.evidence);
        loadSession(session.id, toThread(session.messages));
        return true;
      } catch (err) {
        setError(describeError(err, "Could not open this conversation"));
        return false;
      } finally {
        setBusyId(null);
      }
    },
    [clearEvidence, setEvidence, loadSession]
  );

  const remove = useCallback(
    async (id: string) => {
      setBusyId(id);
      setError(null);
      try {
        await deleteSession(id);
        setItems((prev) => prev.filter((s) => s.id !== id));
        setTotal((t) => Math.max(0, t - 1));
        // Deleting the open conversation starts a fresh one.
        if (id === currentId) {
          resetThread();
          clearEvidence();
        }
      } catch (err) {
        setError(describeError(err, "Could not delete this conversation"));
      } finally {
        setBusyId(null);
      }
    },
    [currentId, resetThread, clearEvidence]
  );

  return {
    items,
    total,
    loading,
    busyId,
    error,
    currentId,
    hasMore: items.length < total,
    loadMore: () => loadPage(items.length),
    reopen,
    remove,
  };
}
