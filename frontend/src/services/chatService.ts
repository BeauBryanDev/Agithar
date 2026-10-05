// POST /chat/stream. The reply arrives as server-sent events, which axios
// cannot read as a stream, so this one file uses fetch.

import { API_BASE_URL, authHeaders, reportUnauthorized } from "./apiClient";
import type { ChatReply, ChatStreamEvent } from "../types/chat";
import type { DetectorResult } from "../types/detector";

const UNAUTHORIZED = 401;
const DATA_PREFIX = "data: ";
const EVENT_SEPARATOR = "\n\n";

export interface ChatHandlers {
  onStatus: (text: string) => void;
  onToken: (answerSoFar: string) => void;
  onEvidence: (evidence: DetectorResult[]) => void;
  onDone: (reply: ChatReply) => void;
  onError: (message: string) => void;
}

function dispatch(event: ChatStreamEvent, handlers: ChatHandlers): void {
  switch (event.type) {
    case "status":
      handlers.onStatus(event.text);
      break;
    case "token":
      handlers.onToken(event.text);
      break;
    case "evidence":
      handlers.onEvidence(event.evidence);
      break;
    case "error":
      handlers.onError(event.text);
      break;
    case "done":
      handlers.onDone(event.reply);
      break;
  }
}

function parseEvent(block: string): ChatStreamEvent | null {
  const line = block.split("\n").find((l) => l.startsWith(DATA_PREFIX));
  if (!line) return null;
  try {
    return JSON.parse(line.slice(DATA_PREFIX.length)) as ChatStreamEvent;
  } catch {
    return null;
  }
}

async function failureMessage(response: Response): Promise<string> {
  try {
    const body = await response.json();
    if (typeof body?.detail === "string") return body.detail;
  } catch {
    // not JSON: fall through
  }
  return `The server answered ${response.status}`;
}

export async function streamChat(
  input: string,
  sessionId: string | null,
  handlers: ChatHandlers,
  signal?: AbortSignal
): Promise<void> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/chat/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders() },
      body: JSON.stringify(
        sessionId ? { input, session_id: sessionId } : { input }
      ),
      signal,
    });
  } catch (err) {
    if (signal?.aborted) return;
    handlers.onError("Could not reach the server");
    return;
  }

  if (response.status === UNAUTHORIZED) {
    reportUnauthorized();
    handlers.onError("Your session expired. Sign in again.");
    return;
  }
  if (!response.ok || !response.body) {
    handlers.onError(await failureMessage(response));
    return;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let cut = buffer.indexOf(EVENT_SEPARATOR);
      while (cut >= 0) {
        const event = parseEvent(buffer.slice(0, cut));
        buffer = buffer.slice(cut + EVENT_SEPARATOR.length);
        if (event) dispatch(event, handlers);
        cut = buffer.indexOf(EVENT_SEPARATOR);
      }
    }
  } catch {
    if (!signal?.aborted) handlers.onError("The connection was interrupted");
  }
}
