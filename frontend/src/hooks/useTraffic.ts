import { useEffect, useState } from "react";
import { fetchTraffic } from "../services/trafficService";
import type { TrafficData } from "../types/traffic";

const POLL_MS = 15_000;

export function useTraffic(minutes: number): {
  data: TrafficData | null;
  error: string | null;
} {
  const [data, setData] = useState<TrafficData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setData(null);

    const poll = async () => {
      if (document.hidden) return;
      try {
        const next = await fetchTraffic(minutes);
        if (!alive) return;
        setData(next);
        setError(null);
      } catch (err) {
        if (alive) setError(err instanceof Error ? err.message : "Traffic failed");
      }
    };

    void poll();
    const timer = window.setInterval(() => void poll(), POLL_MS);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [minutes]);

  return { data, error };
}
