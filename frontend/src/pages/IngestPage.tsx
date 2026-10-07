import { useRef, useState, type DragEvent } from "react";
import { UploadCloud, FileText, CheckCircle2, AlertTriangle, Loader2 } from "lucide-react";
import { Panel } from "../components/common/Panel";
import { useFileUpload } from "../hooks/useFileUpload";
import { IngestResultCard } from "../components/ingest/IngestResultCard";
import { Button } from "../components/common/Button";
import { formatBytes } from "../utils/formatters";
import { maxUploadBytes } from "../services/ingestService";

export function IngestPage() {
  const { items, handleFiles, clear } = useFileUpload();
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const limitLabel = formatBytes(maxUploadBytes());

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
  };

  return (
    <div className="mx-auto max-w-4xl p-4">
      <Panel title="Ingest — Analyse a file with the sensors" bodyClassName="p-4">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          onClick={() => inputRef.current?.click()}
          className={`flex cursor-pointer flex-col items-center justify-center gap-3 border border-dashed py-14 transition-colors ${
            dragging
              ? "border-neon bg-panel-2"
              : "border-hairline hover:border-electric"
          }`}
        >
          <UploadCloud
            className={`h-10 w-10 ${dragging ? "text-neon" : "text-dim"}`}
            strokeWidth={1.5}
          />
          <p className="text-sm font-medium text-secondary">
            Drop an access log, event ids or a flow CSV to analyse it
          </p>
          <p className="font-mono text-[11px] text-dim">
            .log · .txt · .csv — up to {limitLabel}, analysed by the sensors, nothing is saved
          </p>
          <input
            ref={inputRef}
            type="file"
            multiple
            accept=".log,.txt,.csv"
            className="hidden"
            onChange={(e) => e.target.files && handleFiles(e.target.files)}
          />
        </div>

        {items.length > 0 && (
          <>
            <div className="mt-4 flex justify-end">
              <Button variant="ghost" onClick={clear}>
                Clear results
              </Button>
            </div>
            <ul className="mt-2 flex flex-col gap-3">
              {items.map((it) => (
                <li
                  key={it.id}
                  className="hud-corners border border-hairline bg-panel-2 px-4 py-3"
                >
                  <div className="flex items-center gap-3">
                    <FileText className="h-4 w-4 shrink-0 text-dim" strokeWidth={1.75} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-mono text-xs text-primary">
                        {it.filename}
                      </p>
                      <p className="font-mono text-[10px] text-dim">
                        {formatBytes(it.size)}
                        {it.status === "uploading" &&
                          ` · uploading ${Math.round(it.progress * 100)}%`}
                        {it.status === "analysing" && " · the sensors are analysing it…"}
                      </p>
                      {it.error && (
                        <p className="font-mono text-[11px] text-sev-critical">
                          {it.error}
                        </p>
                      )}
                    </div>
                    {(it.status === "uploading" || it.status === "analysing") && (
                      <Loader2 className="h-4 w-4 animate-spin text-electric" />
                    )}
                    {it.status === "done" && (
                      <CheckCircle2 className="h-4 w-4 text-sev-low" />
                    )}
                    {it.status === "error" && (
                      <AlertTriangle className="h-4 w-4 text-sev-critical" />
                    )}
                  </div>
                  {it.result && <IngestResultCard result={it.result} />}
                </li>
              ))}
            </ul>
          </>
        )}
      </Panel>
    </div>
  );
}
