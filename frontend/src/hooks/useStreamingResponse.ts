// Reusable chat logic. Wires the chat stream into the console and detector
// stores. One concern: send a message and stream Agithar's answer.

import { useCallback, useRef } from "react";
import { streamChat } from "../services/chatService";
import { useAnalysisStore } from "../store/useAnalysisStore";
import { useDetectorStore } from "../store/useDetectorStore";
import { useUIStore } from "../store/useUIStore";
import type { AnalysisMessage } from "../types/analysis";

function uid(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

export function useStreamingResponse() {
  const abortRef = useRef<AbortController | null>(null);

  const addMessage = useAnalysisStore((s) => s.addMessage);
  const updateStreamingContent = useAnalysisStore(
    (s) => s.updateStreamingContent
  );
  const finalizeStreaming = useAnalysisStore((s) => s.finalizeStreaming);
  const setStreaming = useAnalysisStore((s) => s.setStreaming);
  const setSessionId = useAnalysisStore((s) => s.setSessionId);
  const setStatusLine = useAnalysisStore((s) => s.setStatusLine);
  const setEvidence = useDetectorStore((s) => s.setEvidence);
  const setDetectorsActive = useUIStore((s) => s.setDetectorsActive);

  const run = useCallback(
    async (input: string) => {
      const controller = new AbortController();
      abortRef.current = controller;

      const analystMsg: AnalysisMessage = {
        id: uid("msg-analyst"),
        role: "analyst",
        content: input,
        created_at: new Date().toISOString(),
      };
      addMessage(analystMsg);

      const systemId = uid("msg-system");
      const systemMsg: AnalysisMessage = {
        id: systemId,
        role: "system",
        content: "",
        streaming: true,
        created_at: new Date().toISOString(),
      };
      addMessage(systemMsg);

      setStreaming(true);
      setDetectorsActive(true);

      const finish = () => {
        setStreaming(false);
        setStatusLine(null);
        setDetectorsActive(false);
      };

      await streamChat(
        input,
        useAnalysisStore.getState().sessionId,
        {
          onStatus: (text) => setStatusLine(text),
          onEvidence: (evidence) => setEvidence(evidence),
          onToken: (answerSoFar) => {
            setStatusLine(null);
            updateStreamingContent(systemId, answerSoFar);
          },
          onDone: (reply) => {
            setSessionId(reply.session_id);
            updateStreamingContent(systemId, reply.message.content);
            finalizeStreaming(systemId, reply.message.evidence_refs);
            if (reply.evidence.length > 0) setEvidence(reply.evidence);
            finish();
          },
          onError: (message) => {
            updateStreamingContent(systemId, `Chat failed — ${message}`);
            finalizeStreaming(systemId, []);
            finish();
          },
        },
        controller.signal
      );
    },
    [
      addMessage,
      updateStreamingContent,
      finalizeStreaming,
      setStreaming,
      setSessionId,
      setStatusLine,
      setEvidence,
      setDetectorsActive,
    ]
  );

  const cancel = useCallback(() => {
    abortRef.current?.abort();
    setStreaming(false);
    setStatusLine(null);
    setDetectorsActive(false);
  }, [setStreaming, setStatusLine, setDetectorsActive]);

  return { run, cancel };
}
