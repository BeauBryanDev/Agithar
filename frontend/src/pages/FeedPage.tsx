import { useEffect, useMemo, useState } from "react";
import { Panel } from "../components/common/Panel";
import { EmptyState } from "../components/common/EmptyState";
import { FeedFilters } from "../components/feed/FeedFilters";
import { DetectionTable } from "../components/feed/DetectionTable";
import { useFeedStore } from "../store/useFeedStore";
import { fetchFeed } from "../services/incidentService";
import { ShieldAlert } from "lucide-react";

const REFRESH_MS = 30_000;

export function FeedPage() {
  const rows = useFeedStore((s) => s.rows);
  const filters = useFeedStore((s) => s.filters);
  const setRows = useFeedStore((s) => s.setRows);
  const setSeverity = useFeedStore((s) => s.setSeverityFilter);
  const setSource = useFeedStore((s) => s.setSourceFilter);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      fetchFeed()
        .then((items) => {
          if (!alive) return;
          setRows(items);
          setError(null);
        })
        .catch((err) => {
          if (alive) setError(err instanceof Error ? err.message : "Feed failed");
        });
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [setRows]);

  const filtered = useMemo(() => {
    return rows.filter((r) => {
      const sevOk = filters.severity === "all" || r.severity === filters.severity;
      const srcOk =
        filters.source === "" ||
        r.ip.toLowerCase().includes(filters.source.toLowerCase());
      return sevOk && srcOk;
    });
  }, [rows, filters]);

  return (
    <div className="p-4">
      <Panel
        title={`Incident Feed — ${filtered.length} incidents`}
        actions={
          <FeedFilters
            severity={filters.severity}
            source={filters.source}
            onSeverity={setSeverity}
            onSource={setSource}
          />
        }
      >
        {error ? (
          <EmptyState
            icon={<ShieldAlert className="h-8 w-8" strokeWidth={1.5} />}
            title="Could not load the feed"
            hint={error}
          />
        ) : (
          <DetectionTable rows={filtered} />
        )}
      </Panel>
    </div>
  );
}
