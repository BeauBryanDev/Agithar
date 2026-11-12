import { useEffect, useState } from "react";
import { Download } from "lucide-react";
import { Panel } from "../common/Panel";
import {
  downloadNavigatorLayer,
  fetchCoverage,
} from "../../services/coverageService";
import type {
  CoverageData,
  CoverageLevel,
  CoverageRow,
} from "../../types/coverage";

const MAX_ROWS = 6;
const ATTACK_URL = "https://attack.mitre.org/techniques/";

const LEVELS: { level: CoverageLevel; label: string; bar: string }[] = [
  { level: 3, label: "Watched by a live sensor", bar: "bg-sev-low" },
  { level: 2, label: "Rule ready, log collected", bar: "bg-sev-medium" },
  { level: 1, label: "Rule exists, log missing", bar: "bg-sev-high" },
  { level: 0, label: "Blind", bar: "bg-sev-critical" },
];

function techniqueUrl(technique: string): string {
  return ATTACK_URL + technique.replace(".", "/") + "/";
}

/** Own incidents first, then the techniques most threat groups use. */
function topOf(rows: CoverageRow[], level: CoverageLevel): CoverageRow[] {
  return rows
    .filter((row) => row.level === level)
    .sort(
      (a, b) =>
        b.incidents - a.incidents ||
        b.threat_groups - a.threat_groups ||
        a.technique.localeCompare(b.technique)
    )
    .slice(0, MAX_ROWS);
}

function LevelBar({ data }: { data: CoverageData }) {
  const total = Math.max(data.summary.techniques_in_scope, 1);
  const count = (level: CoverageLevel) =>
    data.summary.levels.find((item) => item.level === level)?.techniques ?? 0;

  return (
    <div>
      <div className="flex h-3 w-full overflow-hidden rounded-sm bg-void">
        {LEVELS.map((item) => (
          <div
            key={item.level}
            className={item.bar}
            style={{ width: `${(count(item.level) / total) * 100}%` }}
            title={`${item.label}: ${count(item.level)}`}
          />
        ))}
      </div>
      <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2 lg:grid-cols-4">
        {LEVELS.map((item) => (
          <div key={item.level} className="flex items-start gap-2">
            <span className={`mt-1 h-2 w-2 shrink-0 rounded-full ${item.bar}`} />
            <div>
              <div className="font-mono text-lg tabular-nums text-primary">
                {count(item.level)}
              </div>
              <div className="font-mono text-[10px] uppercase tracking-wider text-secondary">
                {item.label}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function hintOf(row: CoverageRow): string {
  if (row.sensors.length > 0) return row.sensors.join(", ");
  if (row.usable_rules > 0) {
    return `${row.usable_rules} usable of ${row.rules} rules`;
  }
  if (row.rules > 0) return `needs ${row.missing_logs.join(", ")}`;
  return `used by ${row.threat_groups} threat groups`;
}

function TechniqueList({
  title,
  rows,
  empty,
}: {
  title: string;
  rows: CoverageRow[];
  empty: string;
}) {
  return (
    <div>
      <h3 className="mb-2 font-mono text-[10px] uppercase tracking-[0.18em] text-dim">
        {title}
      </h3>
      {rows.length === 0 ? (
        <p className="text-xs text-dim">{empty}</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {rows.map((row) => (
            <li key={row.technique} className="min-w-0">
              <a
                href={techniqueUrl(row.technique)}
                target="_blank"
                rel="noopener noreferrer"
                className="block truncate font-mono text-xs text-primary hover:text-neon"
                title={`${row.technique} ${row.name}`}
              >
                <span className="text-electric">{row.technique}</span> {row.name}
              </a>
              <span className="block truncate font-mono text-[10px] text-dim">
                {hintOf(row)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** How much of ATT&CK the sensors and the collected logs can detect. */
export function CoveragePanel() {
  const [data, setData] = useState<CoverageData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    let alive = true;
    fetchCoverage()
      .then((next) => alive && setData(next))
      .catch((err) => {
        if (alive) setError(err instanceof Error ? err.message : "Coverage failed");
      });
    return () => {
      alive = false;
    };
  }, []);

  const download = async () => {
    setDownloading(true);
    setDownloadError(null);
    try {
      await downloadNavigatorLayer();
    } catch {
      setDownloadError("The layer could not be downloaded.");
    } finally {
      setDownloading(false);
    }
  };

  const actions = (
    <button
      onClick={() => void download()}
      disabled={!data || downloading}
      className="inline-flex items-center gap-1.5 rounded-sm border border-hairline px-2.5 py-1 font-mono text-[11px] uppercase tracking-wider text-secondary transition-colors hover:border-electric hover:text-primary disabled:cursor-not-allowed disabled:opacity-40"
      title="Download a layer file for the MITRE ATT&CK Navigator"
    >
      <Download className="h-3.5 w-3.5" strokeWidth={1.5} />
      Navigator layer
    </button>
  );

  return (
    <Panel
      title="ATT&CK Detection Coverage"
      actions={actions}
      className="mb-4"
      bodyClassName="p-4"
    >
      {error && <p className="text-xs text-sev-high">{error}</p>}
      {!error && !data && (
        <p className="font-mono text-xs text-dim">Loading coverage…</p>
      )}
      {data && (
        <>
          <p className="mb-3 text-xs leading-relaxed text-secondary">
            {data.summary.techniques_in_scope} techniques in scope (ATT&CK v
            {data.attack_version}). Logs collected:{" "}
            {data.collected_logs.join(", ")}. Sigma rules are reference
            material and are not deployed.
          </p>
          <LevelBar data={data} />
          <div className="mt-5 grid gap-5 md:grid-cols-3">
            <TechniqueList
              title="Watched by sensors"
              rows={topOf(data.rows, 3)}
              empty="No live sensor maps to a technique."
            />
            <TechniqueList
              title="Easiest to add"
              rows={topOf(data.rows, 2)}
              empty="No rule fits the collected logs."
            />
            <TechniqueList
              title="Needs a new log"
              rows={topOf(data.rows, 1)}
              empty="Nothing here."
            />
          </div>
          {!data.incidents_available && (
            <p className="mt-4 text-xs text-sev-medium">
              The incident database was not reachable, so techniques seen in
              incidents are not counted.
            </p>
          )}
          {downloadError && (
            <p className="mt-4 text-xs text-sev-high">{downloadError}</p>
          )}
        </>
      )}
    </Panel>
  );
}
