import { useEffect, useState } from "react";
import { fetchSensors } from "../services/sensorService";
import type { SensorsData } from "../types/sensors";

const POLL_MS = 15_000;

export function useSensors(): { data: SensorsData | null; error: string | null } {
  const [data, setData] = useState<SensorsData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;

    const poll = async () => {
      if (document.hidden) return;
      try {
        const next = await fetchSensors();
        if (!alive) return;
        setData(next);
        setError(null);
      } catch (err) {
        if (alive) setError(err instanceof Error ? err.message : "Sensors failed");
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
