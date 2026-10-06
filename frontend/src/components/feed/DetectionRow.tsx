import { useNavigate } from "react-router-dom";
import type { DetectionRow as Row } from "../../types/feed";
import { Badge } from "../common/Badge";
import { formatDateTime, formatScore } from "../../utils/formatters";
import { severityBgClass } from "../../utils/severity";
import { detectorLabel } from "../../utils/detectors";
import { statusClass, statusLabel } from "../../utils/incidents";

interface DetectionRowProps {
  row: Row;
}

export function DetectionRow({ row }: DetectionRowProps) {
  const navigate = useNavigate();
  const open = () => navigate(`/incidents/${encodeURIComponent(row.case_key)}`);

  return (
    <tr
      onClick={open}
      onKeyDown={(e) => {
        if (e.key === "Enter") open();
      }}
      tabIndex={0}
      title="Open incident"
      className="group cursor-pointer border-b border-hairline transition-colors hover:bg-panel-2 focus:bg-panel-2"
    >
      <td className="relative py-2 pl-4 pr-3">
        <span
          className={`absolute left-0 top-0 h-full w-0.5 ${severityBgClass(
            row.severity
          )}`}
        />
        <span className="font-mono text-xs text-dim">
          {formatDateTime(row.created_at)}
        </span>
      </td>
      <td className="px-3 py-2 font-mono text-xs text-secondary">{row.ip}</td>
      <td className="px-3 py-2 font-mono text-[11px] text-secondary">
        {row.sensors.map(detectorLabel).join(", ")}
      </td>
      <td className="px-3 py-2">
        <Badge level={row.severity} />
      </td>
      <td className="px-3 py-2 font-mono text-xs text-primary tabular-nums">
        {formatScore(row.composite_score)}
      </td>
      <td className="px-3 py-2">
        <span className={`font-mono text-xs ${statusClass(row.status)}`}>
          {statusLabel(row.status)}
        </span>
      </td>
      <td className="px-3 py-2 font-mono text-xs text-secondary tabular-nums">
        {row.confidence === null ? "-" : formatScore(row.confidence)}
      </td>
      <td className="px-3 py-2 pr-4 font-mono text-xs text-secondary">
        {row.mitre_technique ?? "-"}
      </td>
    </tr>
  );
}
