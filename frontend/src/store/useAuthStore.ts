// Auth slice: the access token and the signed-in user.
// The token lives in sessionStorage (cleared when the tab closes). There is
// no refresh token: when it expires the user signs in again.

import { create } from "zustand";
import { useAnalysisStore } from "./useAnalysisStore";
import { useDetectorStore } from "./useDetectorStore";
import { configureAuth } from "../services/apiClient";
import { fetchMe, login, type CurrentUser } from "../services/authService";
import { mintGuestToken } from "../services/publicService";

const TOKEN_KEY = "aegis.token";
const MODE_KEY = "aegis.mode";
const EXPIRES_KEY = "aegis.guest_exp";
// A guest token is renewed this long before it runs out.
const RENEW_MARGIN_MS = 60_000;

export type SessionMode = "user" | "guest";

function readKey(key: string): string | null {
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeKey(key: string, value: string | null): void {
  try {
    if (value) sessionStorage.setItem(key, value);
    else sessionStorage.removeItem(key);
  } catch {
    // Storage can be blocked: the session then lasts until the page reloads.
  }
}

function readMode(): SessionMode | null {
  const mode = readKey(MODE_KEY);
  return mode === "guest" || mode === "user" ? mode : null;
}

function readExpiry(): number {
  const value = Number(readKey(EXPIRES_KEY));
  return Number.isFinite(value) ? value : 0;
}

function store(token: string | null, mode: SessionMode | null, exp: number) {
  writeKey(TOKEN_KEY, token);
  writeKey(MODE_KEY, mode);
  writeKey(EXPIRES_KEY, mode === "guest" && exp ? String(exp) : null);
}

interface AuthState {
  token: string | null;
  mode: SessionMode | null; // who holds the token: a signed-in user or a guest
  guestExpiresAt: number; // ms since epoch, guests only
  user: CurrentUser | null;
  restoring: boolean;
  signIn: (username: string, password: string) => Promise<void>;
  enterAsGuest: () => Promise<void>;
  /** A valid guest token, renewed first when it is about to run out. */
  guestToken: (forceRenew?: boolean) => Promise<string>;
  signOut: () => void;
  restore: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: readKey(TOKEN_KEY),
  // A token stored before guests existed belongs to a signed-in user.
  mode: readMode() ?? (readKey(TOKEN_KEY) ? "user" : null),
  guestExpiresAt: readExpiry(),
  user: null,
  restoring: false,

  signIn: async (username, password) => {
    const token = await login(username, password);
    store(token, "user", 0);
    set({ token, mode: "user", guestExpiresAt: 0 });
    try {
      set({ user: await fetchMe() });
    } catch (err) {
      get().signOut();
      throw err;
    }
  },

  enterAsGuest: async () => {
    // Never keep a user's token while a guest session starts.
    const { access_token, expires_in } = await mintGuestToken();
    const exp = Date.now() + expires_in * 1000;
    store(access_token, "guest", exp);
    set({ token: access_token, mode: "guest", guestExpiresAt: exp, user: null });
  },

  guestToken: async (forceRenew = false) => {
    const { token, mode, guestExpiresAt } = get();
    const fresh = guestExpiresAt - Date.now() > RENEW_MARGIN_MS;
    if (token && mode === "guest" && fresh && !forceRenew) return token;
    const next = await mintGuestToken();
    const exp = Date.now() + next.expires_in * 1000;
    store(next.access_token, "guest", exp);
    set({ token: next.access_token, mode: "guest", guestExpiresAt: exp });
    return next.access_token;
  },

  signOut: () => {
    store(null, null, 0);
    // The next person on this browser must not see this conversation.
    useAnalysisStore.getState().reset();
    useAnalysisStore.persist.clearStorage();
    useDetectorStore.getState().clear();
    useDetectorStore.persist.clearStorage();
    set({
      token: null,
      mode: null,
      guestExpiresAt: 0,
      user: null,
      restoring: false,
    });
  },

  // After a page reload the token is still there but the user is not.
  restore: async () => {
    // A guest has no account to load.
    if (get().mode !== "user") return;
    if (!get().token || get().user || get().restoring) return;
    set({ restoring: true });
    try {
      set({ user: await fetchMe(), restoring: false });
    } catch {
      get().signOut();
    }
  },
}));

configureAuth(
  () => useAuthStore.getState().token,
  () => {
    // A guest is never signed out by a refused request: the pages that are
    // not open to guests just show the server's message, and the visitor chat
    // renews the token by itself.
    if (useAuthStore.getState().mode === "guest") return;
    useAuthStore.getState().signOut();
  },
  () => useAuthStore.getState().mode === "guest",
  () => useAuthStore.getState().guestToken()
);
