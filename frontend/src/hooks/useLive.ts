import { useEffect, useState } from "react";
import { fetchLive } from "../services/liveService";
import type { LiveData } from "../types/live";

const POLL_MS = 4_000;

export function useLive(): { data: LiveData | null; error: string | null } {
  const [data, setData] = useState<LiveData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;

    const poll = async () => {
      if (document.hidden) return;
      try {
        const next = await fetchLive();
        if (!alive) return;
        setData(next);
        setError(null);
      } catch (err) {
        if (alive) setError(err instanceof Error ? err.message : "Live feed failed");
      }
    };

    void poll();
    const timer = window.setInterval(() => void poll(), POLL_MS);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  return { data, error };
}
