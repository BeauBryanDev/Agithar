import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ShieldAlert } from "lucide-react";
import { Badge } from "../components/common/Badge";
import { EmptyState } from "../components/common/EmptyState";
import { VerdictPanel } from "../components/incident/VerdictPanel";
import { SensorScores } from "../components/incident/SensorScores";
import { EvidenceList } from "../components/incident/EvidenceList";
import { ActionList, IocList } from "../components/incident/IocActions";
import { ReportPanel } from "../components/incident/ReportPanel";
import { fetchIncident } from "../services/incidentService";
import type { IncidentDetail } from "../types/incident";
import { formatDateTime } from "../utils/formatters";
import { statusClass, statusLabel } from "../utils/incidents";

const REFRESH_MS = 15_000;

export function IncidentPage() {
  const { caseKey = "" } = useParams();
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setIncident(null);
    setError(null);

    const load = () =>
      fetchIncident(caseKey)
        .then((d) => {
          if (!alive) return;
          setIncident(d);
          setError(null);
        })
        .catch((err) => {
          if (alive) setError(err instanceof Error ? err.message : "Load failed");
        });

    void load();
    // A case still being investigated gets its verdict and report later.
    const timer = window.setInterval(() => {
      if (!document.hidden) void load();
    }, REFRESH_MS);

    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [caseKey]);

  const back = (
    <Link
      to="/feed"
      className="mb-4 inline-flex items-center gap-1.5 font-mono text-xs text-secondary hover:text-primary"
    >
      <ArrowLeft className="h-3.5 w-3.5" /> Incident feed
    </Link>
  );

  if (error && !incident) {
    return (
      <div className="p-4">
        {back}
        <EmptyState
          icon={<ShieldAlert className="h-8 w-8" strokeWidth={1.5} />}
          title="Could not load the incident"
          hint={error}
        />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="p-4">
        {back}
        <p className="font-mono text-xs text-dim">Loading incident…</p>
      </div>
    );
  }

  return (
    <div className="p-4">
      {back}

      <div className="mb-4 flex flex-wrap items-center gap-x-4 gap-y-2">
        <Badge level={incident.severity} />
        <h1 className="font-mono text-lg font-semibold text-primary">
          {incident.ip}
        </h1>
        <span className={`font-mono text-xs uppercase ${statusClass(incident.status)}`}>
          {statusLabel(incident.status)}
        </span>
        <span className="font-mono text-[11px] text-dim">
          opened {formatDateTime(incident.created_at)} · updated{" "}
          {formatDateTime(incident.updated_at)}
        </span>
        <span className="break-all font-mono text-[10px] text-dim">
          case {incident.case_key}
        </span>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <div className="flex flex-col gap-4">
          <VerdictPanel incident={incident} />
          <SensorScores incident={incident} />
        </div>
        <div className="flex flex-col gap-4">
          <EvidenceList evidence={incident.evidence} />
          <IocList iocs={incident.iocs} />
          <ActionList actions={incident.actions} />
        </div>
        <ReportPanel incident={incident} />
      </div>
    </div>
  );
}
