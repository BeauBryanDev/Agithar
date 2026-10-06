import { useEffect, useRef, useState } from "react";
import { fetchTelemetry } from "../services/telemetryService";
import type { Telemetry } from "../types/telemetry";

const POLL_MS = 5_000;
const HISTORY = 36; // about 3 minutes of samples

export interface TelemetryView {
  data: Telemetry | null;
  error: string | null;
  cpuHistory: number[];
  memHistory: number[];
  rxPerSecond: number | null;
  txPerSecond: number | null;
}

function push(list: number[], value: number): number[] {
  return [...list, value].slice(-HISTORY);
}

/** Polls /telemetry; pauses while the tab is hidden. */
export function useTelemetry(): TelemetryView {
  const [view, setView] = useState<TelemetryView>({
    data: null,
    error: null,
    cpuHistory: [],
    memHistory: [],
    rxPerSecond: null,
    txPerSecond: null,
  });
  const previous = useRef<Telemetry | null>(null);

  useEffect(() => {
    let alive = true;

    const poll = async () => {
      if (document.hidden) return;
      try {
        const next = await fetchTelemetry();
        if (!alive) return;
        const before = previous.current;
        previous.current = next;

        let rx: number | null = null;
        let tx: number | null = null;
        const dt = before ? next.sampled_at - before.sampled_at : 0;
        if (before?.server && next.server && dt > 0) {
          rx = Math.max(0, next.server.net_bytes_recv - before.server.net_bytes_recv) / dt;
          tx = Math.max(0, next.server.net_bytes_sent - before.server.net_bytes_sent) / dt;
        }

        setView((v) => ({
          data: next,
          error: null,
          cpuHistory: next.server ? push(v.cpuHistory, next.server.cpu_percent) : v.cpuHistory,
          memHistory: next.server ? push(v.memHistory, next.server.memory_percent) : v.memHistory,
          rxPerSecond: rx,
          txPerSecond: tx,
        }));
      } catch (err) {
        if (alive) {
          setView((v) => ({
            ...v,
            error: err instanceof Error ? err.message : "Telemetry failed",
          }));
        }
      }
    };

    void poll();
    const timer = window.setInterval(() => void poll(), POLL_MS);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  return view;
}
