import { ConversationThread } from "../components/console/ConversationThread";
import { AnalysisInput } from "../components/console/AnalysisInput";
import { EvidencePanel } from "../components/console/EvidencePanel";
import { Panel } from "../components/common/Panel";
import { useAnalysisStore } from "../store/useAnalysisStore";
import { useDetectorStore } from "../store/useDetectorStore";
import { useStreamingResponse } from "../hooks/useStreamingResponse";
import { useEvidenceLink } from "../hooks/useEvidenceLink";
import { Button } from "../components/common/Button";
import { useAuthStore } from "../store/useAuthStore";
import { GUEST_MESSAGE_MAX_CHARS } from "../services/publicService";

export function ConsolePage() {
  const messages = useAnalysisStore((s) => s.messages);
  const streaming = useAnalysisStore((s) => s.streaming);
  const statusLine = useAnalysisStore((s) => s.statusLine);
  const resetThread = useAnalysisStore((s) => s.reset);
  const remaining = useAnalysisStore((s) => s.remaining);
  const guest = useAuthStore((s) => s.mode === "guest");
  const clearEvidence = useDetectorStore((s) => s.clear);

  const evidence = useDetectorStore((s) => s.evidence);
  const expanded = useDetectorStore((s) => s.expanded);
  const toggleExpanded = useDetectorStore((s) => s.toggleExpanded);

  const { run, cancel } = useStreamingResponse();
  const { activeEvidenceId, activate } = useEvidenceLink();

  return (
    <div
      className={`grid h-full grid-rows-1 gap-4 p-4 ${
        guest ? "mx-auto max-w-4xl" : "lg:grid-cols-[55fr_45fr]"
      }`}
    >
      {/* Left: conversation console */}
      <Panel
        title="Agithar"
        actions={
          <div className="flex items-center gap-3">
            {guest && remaining !== null && (
              <span className="font-mono text-[10px] uppercase tracking-wider text-dim">
                {remaining} messages left
              </span>
            )}
            <Button
              variant="ghost"
              disabled={streaming}
              onClick={() => {
                resetThread();
                clearEvidence();
              }}
            >
              New session
            </Button>
          </div>
        }
        className="flex min-h-0 flex-col"
        bodyClassName="flex min-h-0 flex-1 flex-col"
      >
        <div className="min-h-0 flex-1 overflow-auto">
          <ConversationThread
            messages={messages}
            activeEvidenceId={activeEvidenceId}
            onHoverClaim={activate}
          />
        </div>
        {statusLine && (
          <p className="aegis-fade-in px-4 pb-2 font-mono text-[11px] text-electric">
            {statusLine}…
          </p>
        )}
        <AnalysisInput
          streaming={streaming}
          onSubmit={run}
          onCancel={cancel}
          maxChars={guest ? GUEST_MESSAGE_MAX_CHARS : undefined}
          placeholder={
            guest
              ? "Ask about attacks, CVEs or MITRE techniques, or paste a short payload…"
              : undefined
          }
        />
      </Panel>

      {!guest && (
        <>
      {/* Right: evidence */}
      <Panel
        title="Evidence — Detector Output"
        className="flex min-h-0 flex-col"
        bodyClassName="min-h-0 flex-1 overflow-auto"
      >
        <EvidencePanel
          evidence={evidence}
          expanded={expanded}
          activeEvidenceId={activeEvidenceId}
          onToggle={toggleExpanded}
          onHover={activate}
        />
      </Panel>
        </>
      )}
    </div>
  );
}
