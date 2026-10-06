import { useRef, useState, type DragEvent } from "react";
import { UploadCloud, FileText, CheckCircle2, AlertTriangle, Loader2 } from "lucide-react";
import { Panel } from "../components/common/Panel";
import { useFileUpload } from "../hooks/useFileUpload";
import { formatBytes } from "../utils/formatters";

export function IngestPage() {
  const { items, handleFiles } = useFileUpload();
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files);
  };

  return (
    <div className="mx-auto max-w-3xl p-4">
      <Panel title="Ingest — Route to Detector" bodyClassName="p-4">
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
            Drop a log, capture, or email to begin analysis
          </p>
          <p className="font-mono text-[11px] text-dim">
            .log · NetFlow .csv · .pcap · .eml
          </p>
          <input
            ref={inputRef}
            type="file"
            multiple
            accept=".log,.csv,.pcap,.eml"
            className="hidden"
            onChange={(e) => e.target.files && handleFiles(e.target.files)}
          />
        </div>

        {items.length > 0 && (
          <ul className="mt-4 flex flex-col gap-2">
            {items.map((it) => (
              <li
                key={it.id}
                className="hud-corners flex items-center gap-3 border border-hairline bg-panel-2 px-3 py-2.5"
              >
                <FileText className="h-4 w-4 shrink-0 text-dim" strokeWidth={1.75} />
                <div className="min-w-0 flex-1">
                  <p className="truncate font-mono text-xs text-primary">
                    {it.filename}
                  </p>
                  <p className="font-mono text-[10px] text-dim">
                    {formatBytes(it.size)}
                    {it.routed_to && (
                      <>
                        {" · "}
                        <span className="text-electric">
                          {it.routed_to} processing…
                        </span>
                      </>
                    )}
                  </p>
                  {it.error && (
                    <p className="font-mono text-[10px] text-sev-critical">
                      {it.error}
                    </p>
                  )}
                </div>
                {it.status === "processing" && (
                  <Loader2 className="h-4 w-4 animate-spin text-electric" />
                )}
                {it.status === "done" && (
                  <CheckCircle2 className="h-4 w-4 text-sev-low" />
                )}
                {it.status === "error" && (
                  <AlertTriangle className="h-4 w-4 text-sev-critical" />
                )}
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
