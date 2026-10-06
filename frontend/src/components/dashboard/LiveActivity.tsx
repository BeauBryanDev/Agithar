import { Panel } from "../common/Panel";
import { LiveEventFeed } from "./LiveEventFeed";
import { RequestsPerMinute } from "./RequestsPerMinute";
import { TopList } from "./TopList";
import { useLive } from "../../hooks/useLive";
import { detectorLabel } from "../../utils/detectors";

/** Live anomalies, request rate and the busiest sources, from the log feed. */
export function LiveActivity() {
  const { data, error } = useLive();

  if (!data) {
    return (
      <p className="mb-4 font-mono text-xs text-dim">
        {error ? `Live feed unavailable: ${error}` : "Reading live feed…"}
      </p>
    );
  }

  const totalRequests = data.per_minute.reduce((n, p) => n + p.requests, 0);
  const lastMinute = data.per_minute[data.per_minute.length - 1];

  return (
    <div className="mb-4 grid gap-4 xl:grid-cols-3">
      <Panel
        title={`Live anomalies · ${data.anomalies_in_window} in the last ${data.window_minutes} min`}
        className="xl:col-span-2"
        actions={
          <span className="font-mono text-[10px] uppercase tracking-wider text-dim">
            {data.enabled
              ? data.log_only
                ? "log only"
                : "live alerts"
              : "ingestion off"}
          </span>
        }
      >
        <LiveEventFeed events={data.events} />
      </Panel>

      <div className="flex flex-col gap-4">
        <Panel
          title="Requests per minute"
          bodyClassName="p-4"
          actions={
            <span className="font-mono text-[10px] text-secondary">
              {lastMinute?.requests ?? 0}/min now · {totalRequests} in {data.window_minutes} min
            </span>
          }
        >
          {data.enabled ? (
            <RequestsPerMinute data={data.per_minute} />
          ) : (
            <p className="text-xs text-dim">
              Request rates appear once the log feed runs.
            </p>
          )}
        </Panel>

        <Panel title="Top attacking IPs" bodyClassName="p-4">
          <TopList
            empty="No anomalous sources yet."
            rows={data.top_ips.map((t) => ({
              label: t.ip,
              count: t.count,
              hint: `${t.sensors.map(detectorLabel).join(", ")} · max ${t.max_score.toFixed(2)}`,
            }))}
          />
        </Panel>

        <Panel title="Top targeted paths" bodyClassName="p-4">
          <TopList
            empty="No anomalous paths yet."
            rows={data.top_paths.map((t) => ({ label: t.path, count: t.count }))}
          />
        </Panel>
      </div>
    </div>
  );
}
