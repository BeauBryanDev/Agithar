import type { DetectionRow as Row } from "../../types/feed";
import { DetectionRow } from "./DetectionRow";
import { EmptyState } from "../common/EmptyState";
import { ListFilter } from "lucide-react";

interface DetectionTableProps {
  rows: Row[];
}

const HEADERS = [
  "Time",
  "Source",
  "Sensors",
  "Severity",
  "Score",
  "Status",
  "Confidence",
  "MITRE",
];

export function DetectionTable({ rows }: DetectionTableProps) {
  if (rows.length === 0) {
    return (
      <EmptyState
        icon={<ListFilter className="h-8 w-8" strokeWidth={1.5} />}
        title="No incidents to show"
        hint="Nothing has been escalated yet, or the filters hide everything."
      />
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr className="border-b border-hairline">
            {HEADERS.map((h) => (
              <th
                key={h}
                className="px-3 py-2 text-left font-mono text-[10px] font-medium uppercase tracking-[0.15em] text-dim first:pl-4 last:pr-4"
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <DetectionRow key={r.incident_id} row={r} />
          ))}
        </tbody>
      </table>
    </div>
  );
}
