import { useState } from "react";
import { CVESearchBar } from "../components/vuln/CVESearchBar";
import { CVECard } from "../components/vuln/CVECard";
import { EmptyState } from "../components/common/EmptyState";
import { ShieldAlert } from "lucide-react";
import type { CVERecord } from "../types/vulnerability";
import { searchVulnerabilities } from "../services/vulnService";

const DEFAULT_HINT = "Enter a CVE ID such as CVE-2021-44228.";

export function VulnLookupPage() {
  const [results, setResults] = useState<CVERecord[]>([]);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);

  const runSearch = async (query: string) => {
    if (!query) return;
    setLoading(true);
    setError(null);
    try {
      const res = await searchVulnerabilities(query);
      setResults(res.results);
      setNote(res.note ?? null);
    } catch (err) {
      setResults([]);
      setNote(null);
      setError(err instanceof Error ? err.message : "Lookup failed");
    } finally {
      setLoading(false);
      setSearched(true);
    }
  };

  return (
    <div className="mx-auto max-w-3xl p-4">
      <div className="mb-4">
        <h1 className="mb-1 text-lg font-semibold text-primary">
          Vulnerability Lookup
        </h1>
        <p className="text-xs text-secondary">
          Look up a CVE by ID: CVSS score, affected products, weakness and
          OWASP category, and known public exploits. The local dataset ends in
          mid-2025; newer records come live from NVD.
        </p>
      </div>

      <CVESearchBar onSearch={runSearch} loading={loading} />

      <div className="mt-5 flex flex-col gap-3">
        {error ? (
          <EmptyState
            icon={<ShieldAlert className="h-8 w-8" strokeWidth={1.5} />}
            title="Lookup failed"
            hint={error}
          />
        ) : results.length === 0 && !loading ? (
          <EmptyState
            icon={<ShieldAlert className="h-8 w-8" strokeWidth={1.5} />}
            title={searched ? "No matching record" : "Search a CVE"}
            hint={searched ? (note ?? DEFAULT_HINT) : DEFAULT_HINT}
          />
        ) : (
          <>
            {results.map((r) => (
              <CVECard key={r.cve_id} record={r} />
            ))}
            {note && <p className="text-xs text-dim">{note}</p>}
          </>
        )}
      </div>
    </div>
  );
}
