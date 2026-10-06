// Auth slice: the access token and the signed-in user.
// The token lives in sessionStorage (cleared when the tab closes). There is
// no refresh token: when it expires the user signs in again.

import { create } from "zustand";
import { useAnalysisStore } from "./useAnalysisStore";
import { useDetectorStore } from "./useDetectorStore";
import { configureAuth } from "../services/apiClient";
import { fetchMe, login, type CurrentUser } from "../services/authService";

const TOKEN_KEY = "aegis.token";

function readToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function writeToken(token: string | null): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Storage can be blocked: the session then lasts until the page reloads.
  }
}

interface AuthState {
  token: string | null;
  user: CurrentUser | null;
  restoring: boolean;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => void;
  restore: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  token: readToken(),
  user: null,
  restoring: false,

  signIn: async (username, password) => {
    const token = await login(username, password);
    writeToken(token);
    set({ token });
    try {
      set({ user: await fetchMe() });
    } catch (err) {
      get().signOut();
      throw err;
    }
  },

  signOut: () => {
    writeToken(null);
    // The next person on this browser must not see this conversation.
    useAnalysisStore.getState().reset();
    useAnalysisStore.persist.clearStorage();
    useDetectorStore.getState().clear();
    useDetectorStore.persist.clearStorage();
    set({ token: null, user: null, restoring: false });
  },

  // After a page reload the token is still there but the user is not.
  restore: async () => {
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
  () => useAuthStore.getState().signOut()
);
