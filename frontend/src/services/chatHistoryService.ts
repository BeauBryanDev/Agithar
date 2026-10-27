// GET / DELETE /chat/sessions: the signed-in user's past conversations.
// The server only ever returns the caller's own sessions.

import { apiClient } from "./apiClient";
import type { ChatSession, ChatSessionList } from "../types/chat";

export const HISTORY_PAGE_SIZE = 20;

export async function listSessions(skip: number): Promise<ChatSessionList> {
  const { data } = await apiClient.get<ChatSessionList>("/chat/sessions", {
    params: { skip, limit: HISTORY_PAGE_SIZE },
  });
  return data;
}

export async function fetchSession(id: string): Promise<ChatSession> {
  const { data } = await apiClient.get<ChatSession>(
    `/chat/sessions/${encodeURIComponent(id)}`
  );
  return data;
}

export async function deleteSession(id: string): Promise<void> {
  await apiClient.delete(`/chat/sessions/${encodeURIComponent(id)}`);
}
