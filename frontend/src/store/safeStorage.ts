// sessionStorage that never throws: it can be blocked, full or missing.
// Chat state uses it so a page reload keeps the conversation of this tab,
// and it dies with the tab like the sign-in token does.

import type { StateStorage } from "zustand/middleware";

export const safeSessionStorage: StateStorage = {
  getItem: (name) => {
    try {
      return sessionStorage.getItem(name);
    } catch {
      return null;
    }
  },
  setItem: (name, value) => {
    try {
      sessionStorage.setItem(name, value);
    } catch {
      // Quota or blocked storage: the in-memory state still works.
    }
  },
  removeItem: (name) => {
    try {
      sessionStorage.removeItem(name);
    } catch {
      // Nothing to clean up.
    }
  },
};
