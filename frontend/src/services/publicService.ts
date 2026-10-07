// The public demo: a password-less guest token and the visitor chat.
// The guest token only marks a session; the server limits visitors by IP.

import { apiClient } from "./apiClient";

export const GUEST_MESSAGE_MAX_CHARS = 640;
// The server accepts at most 6 history items and 12,000 characters in all.
const HISTORY_ITEMS = 6;
const HISTORY_ITEM_MAX_CHARS = 1800;

export interface GuestToken {
  access_token: string;
  expires_in: number;
  role: string;
}

export interface PublicHistoryItem {
  role: "user" | "assistant";
  content: string;
}

export interface PublicReply {
  reply: string;
  remaining: number | null;
}

export async function mintGuestToken(): Promise<GuestToken> {
  const { data } = await apiClient.post<GuestToken>("/public/visitors");
  if (data.role !== "guest" || typeof data.access_token !== "string") {
    throw new Error("The demo is unavailable");
  }
  return data;
}

/** The last turns, trimmed so they always fit the server's limits. */
export function trimHistory(items: PublicHistoryItem[]): PublicHistoryItem[] {
  return items
    .filter((i) => i.content.trim().length > 0)
    .slice(-HISTORY_ITEMS)
    .map((i) => ({ ...i, content: i.content.slice(0, HISTORY_ITEM_MAX_CHARS) }));
}

export async function sendPublicChat(
  message: string,
  history: PublicHistoryItem[],
  token: string,
  signal?: AbortSignal
): Promise<PublicReply> {
  const { data } = await apiClient.post<PublicReply>(
    "/public/chat",
    { message, history: trimHistory(history) },
    { headers: { Authorization: `Bearer ${token}` }, signal, timeout: 100_000 }
  );
  return {
    reply: String(data.reply ?? ""),
    remaining: typeof data.remaining === "number" ? data.remaining : null,
  };
}
