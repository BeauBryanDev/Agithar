import { Boxes, Bug, Crosshair, ShieldAlert } from "lucide-react";
import type { CVERecord, CVESource } from "../../types/vulnerability";
import { ScoreReadout } from "../common/ScoreReadout";
import { Badge } from "../common/Badge";

interface CVECardProps {
  record: CVERecord;
}

const SOURCE_LABEL: Record<CVESource, string> = {
  local: "local dataset",
  nvd: "NVD (live)",
  cache: "NVD (recent lookup)",
  exploit_db: "Exploit-DB",
};

export function CVECard({ record }: CVECardProps) {
  const { cvss } = record;
  const cwes = record.cwes ?? [];
  const owasp = record.owasp_categories ?? [];
  const exploits = record.exploits ?? [];

  return (
    <article className="relative border border-hairline bg-panel-2 p-4 transition-colors hover:border-electric/50">
      <span className="pointer-events-none absolute -left-px -top-px h-3 w-3 border-l border-t border-electric" />
      <span className="pointer-events-none absolute -right-px -top-px h-3 w-3 border-r border-t border-electric" />

      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm font-semibold text-primary">
              {record.cve_id}
            </span>
            {cvss && <Badge level={cvss.severity} />}
          </div>
          {record.published && (
            <span className="font-mono text-[10px] text-dim">
              published {new Date(record.published).toLocaleDateString("en-CA")}
            </span>
          )}
          {(record.vendor || record.vuln_type) && (
            <p className="font-mono text-[10px] text-dim">
              {[record.vendor, record.vuln_type?.replace(/_/g, " ")]
                .filter(Boolean)
                .join(" · ")}
            </p>
          )}
        </div>
        {cvss ? (
          <ScoreReadout
            label="CVSS"
            value={cvss.base_score.toFixed(1)}
            severity={cvss.severity}
            size="lg"
          />
        ) : (
          <span className="font-mono text-[11px] text-dim">CVSS not scored</span>
        )}
      </div>

      <p className="mt-3 text-sm leading-relaxed text-secondary">
        {record.summary}
      </p>

      <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-hairline pt-3">
        <div className="flex items-center gap-1.5">
          <Boxes className="h-3.5 w-3.5 text-dim" strokeWidth={1.75} />
          <span className="font-mono text-[11px] text-secondary">
            {record.affected_products.length > 0
              ? record.affected_products.join(", ")
              : "affected products not listed"}
          </span>
        </div>
        {record.mitre_technique && (
          <div className="flex items-center gap-1.5">
            <Crosshair className="h-3.5 w-3.5 text-dim" strokeWidth={1.75} />
            <span className="font-mono text-[11px] text-electric">
              {record.mitre_technique}
            </span>
          </div>
        )}
        {cwes.length > 0 && (
          <div className="flex items-center gap-1.5">
            <Bug className="h-3.5 w-3.5 text-dim" strokeWidth={1.75} />
            <span className="font-mono text-[11px] text-secondary">
              {cwes.join(", ")}
            </span>
          </div>
        )}
        {owasp.length > 0 && (
          <span className="font-mono text-[11px] text-secondary">
            OWASP {owasp.join(", ")}
          </span>
        )}
        {exploits.length > 0 && (
          <div className="flex items-center gap-1.5">
            <ShieldAlert className="h-3.5 w-3.5 text-dim" strokeWidth={1.75} />
            <span className="font-mono text-[11px] text-electric">
              {exploits.length} public exploit
              {exploits.length > 1 ? "s" : ""} documented (Exploit-DB)
            </span>
          </div>
        )}
      </div>

      {cvss?.vector && (
        <p className="mt-2 font-mono text-[10px] text-dim">{cvss.vector}</p>
      )}
      {record.source && (
        <p className="mt-1 font-mono text-[10px] text-dim">
          source: {SOURCE_LABEL[record.source]}
        </p>
      )}
    </article>
  );
}
