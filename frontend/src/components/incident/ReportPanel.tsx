import { Panel } from "../common/Panel";
import { MarkdownText } from "../console/MarkdownText";
import type { IncidentDetail } from "../../types/incident";

export function ReportPanel({ incident }: { incident: IncidentDetail }) {
  return (
    <Panel title="Incident report" bodyClassName="p-5">
      {incident.report_md ? (
        <div className="max-h-[40rem] overflow-y-auto pr-2">
          <MarkdownText content={incident.report_md} />
        </div>
      ) : (
        <p className="text-xs leading-relaxed text-secondary">
          {incident.status === "false_positive"
            ? "No report: the master agent closed this case as a false positive."
            : incident.status === "open"
              ? "The report is written after the master agent finishes."
              : "No report was stored for this incident."}
        </p>
      )}
    </Panel>
  );
}
