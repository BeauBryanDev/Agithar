import { useEffect, useState } from "react";
import { fetchHealth, type Health } from "../services/healthService";

const POLL_MS = 30_000;

const UNKNOWN: Health | null = null;

/** Polls the backend readiness endpoint; null until the first answer. */
export function useHealth(): Health | null {
  const [health, setHealth] = useState<Health | null>(UNKNOWN);

  useEffect(() => {
    let alive = true;

    const check = async () => {
      const next = await fetchHealth();
      if (alive) setHealth(next);
    };

    void check();
    const timer = window.setInterval(() => void check(), POLL_MS);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  return health;
}
