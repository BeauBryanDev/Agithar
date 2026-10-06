import { Panel } from "../common/Panel";
import { ScoreReadout } from "../common/ScoreReadout";
import { MarkdownText } from "../console/MarkdownText";
import type { IncidentDetail } from "../../types/incident";
import { formatScore } from "../../utils/formatters";

const VERDICT_LABEL = {
  confirmed: "Confirmed threat",
  false_positive: "False positive",
  needs_human: "Needs human review",
} as const;

const VERDICT_TONE = {
  confirmed: "text-sev-critical",
  false_positive: "text-sev-low",
  needs_human: "text-sev-high",
} as const;

function mitreUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

export function VerdictPanel({ incident }: { incident: IncidentDetail }) {
  const v = incident.verdict;

  if (!v) {
    return (
      <Panel title="Master agent verdict" bodyClassName="p-4">
        <p className="text-xs leading-relaxed text-secondary">
          No verdict yet. The case is{" "}
          {incident.status === "open"
            ? "waiting for, or being investigated by, the master agent."
            : "closed without one."}
        </p>
      </Panel>
    );
  }

  return (
    <Panel title="Master agent verdict" bodyClassName="flex flex-col gap-4 p-4">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <span className={`font-mono text-lg font-semibold ${VERDICT_TONE[v.verdict]}`}>
          {VERDICT_LABEL[v.verdict]}
        </span>
        <ScoreReadout
          label="confidence"
          value={formatScore(v.confidence)}
          size="md"
        />
      </div>

      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 font-mono text-xs">
        <dt className="text-dim">human review</dt>
        <dd className={v.needs_human ? "text-sev-high" : "text-secondary"}>
          {v.needs_human ? "required" : "not required"}
        </dd>
        <dt className="text-dim">MITRE ATT&amp;CK</dt>
        <dd>
          {v.mitre_technique ? (
            <a
              href={mitreUrl(v.mitre_technique)}
              target="_blank"
              rel="noopener noreferrer nofollow"
              className="text-electric underline"
            >
              {v.mitre_technique}
            </a>
          ) : (
            <span className="text-secondary">none</span>
          )}
        </dd>
        <dt className="text-dim">OWASP</dt>
        <dd className="text-secondary">{v.owasp_category ?? "none"}</dd>
        <dt className="text-dim">admin alert</dt>
        <dd className={incident.notified ? "text-electric" : "text-secondary"}>
          {incident.notified
            ? "sent to Telegram"
            : v.verdict === "false_positive"
              ? "not sent (closed quietly)"
              : "not sent"}
        </dd>
      </dl>

      <MarkdownText content={v.summary} />
    </Panel>
  );
}
