import type { DetectorInfo } from "../../types/dashboard";
import { detectorLabel } from "../../utils/detectors";
import { formatScore } from "../../utils/formatters";

interface SensorStatusProps {
  detectors: DetectorInfo[];
}

export function SensorStatus({ detectors }: SensorStatusProps) {
  return (
    <ul className="flex flex-col divide-y divide-hairline">
      {detectors.map((d) => (
        <li
          key={d.name}
          className="flex items-center justify-between gap-3 py-2"
        >
          <div className="flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${
                d.status === "loaded" ? "bg-sev-low" : "bg-sev-critical"
              }`}
            />
            <span className="font-mono text-xs text-primary">
              {detectorLabel(d.name)}
            </span>
          </div>
          <span className="font-mono text-[11px] text-dim">
            {d.status === "failed"
              ? "failed to load"
              : d.threshold === null
                ? "no fixed threshold"
                : `threshold ${formatScore(d.threshold)}`}
          </span>
        </li>
      ))}
    </ul>
  );
}
