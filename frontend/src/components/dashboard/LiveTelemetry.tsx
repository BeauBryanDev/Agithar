import { Panel } from "../common/Panel";
import { Gauge } from "./Gauge";
import { ServiceList } from "./ServiceList";
import { PipelinePanel } from "./PipelinePanel";
import { useTelemetry } from "../../hooks/useTelemetry";
import { formatRate } from "../../utils/formatters";

/** Live server and pipeline numbers; refreshes every few seconds. */
export function LiveTelemetry() {
  const { data, error, cpuHistory, memHistory, rxPerSecond, txPerSecond } =
    useTelemetry();

  if (!data) {
    return (
      <p className="mb-4 font-mono text-xs text-dim">
        {error ? `Telemetry unavailable: ${error}` : "Reading telemetry…"}
      </p>
    );
  }

  const server = data.server;

  return (
    <div className="mb-4 grid gap-4 xl:grid-cols-3">
      <Panel
        title="Server · live"
        className="xl:col-span-2"
        bodyClassName="p-4"
        actions={
          error ? (
            <span className="font-mono text-[10px] text-sev-high">stale</span>
          ) : (
            <span className="aegis-live-dot h-2 w-2 rounded-full bg-neon" />
          )
        }
      >
        {server === null ? (
          <p className="text-xs text-secondary">
            Server metrics are not available.
          </p>
        ) : (
          <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
            <Gauge label="cpu" value={server.cpu_percent} history={cpuHistory} />
            <Gauge
              label="memory"
              value={server.memory_percent}
              history={memHistory}
            />
            <Gauge
              label="disk /"
              value={server.disk_percent}
              detail={`${server.disk_free_gb.toFixed(1)} GB free`}
            />
            <div className="flex flex-col gap-2">
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
                network
              </span>
              <span className="font-mono text-sm tabular-nums text-electric">
                ↓ {formatRate(rxPerSecond)}
              </span>
              <span className="font-mono text-sm tabular-nums text-neon">
                ↑ {formatRate(txPerSecond)}
              </span>
            </div>
          </div>
        )}
        {server && (
          <div className="mt-4 grid gap-4 border-t border-hairline pt-3 sm:grid-cols-2">
            <ServiceList title="Protected apps" states={server.siblings} />
            <ServiceList title="System services" states={server.system} />
          </div>
        )}
      </Panel>

      <Panel title="Pipeline" bodyClassName="p-4">
        <PipelinePanel pipeline={data.pipeline} />
      </Panel>
    </div>
  );
}
