import { User } from "lucide-react";
import agitharIcon from "../../assets/agithar.svg";
import type { AnalysisMessage } from "../../types/analysis";
import { StreamingText } from "./StreamingText";
import { formatTime } from "../../utils/formatters";

interface MessageBubbleProps {
  message: AnalysisMessage;
  activeEvidenceId: string | null;
  onHoverClaim: (id: string | null) => void;
}

export function MessageBubble({
  message,
  activeEvidenceId,
  onHoverClaim,
}: MessageBubbleProps) {
  const isAnalyst = message.role === "analyst";

  return (
    <div className="flex gap-3">
      <div
        className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-sm border ${
          isAnalyst
            ? "border-hairline bg-panel-2 text-secondary"
            : "border-electric/40 bg-panel-2 text-electric"
        }`}
      >
        {isAnalyst ? (
          <User className="h-3.5 w-3.5" strokeWidth={1.75} />
        ) : (
          <img src={agitharIcon} alt="Agithar" className="h-5 w-5" />
        )}
      </div>

      <div className="min-w-0 flex-1">
        <div className="mb-1 flex items-center gap-2">
          <span className="text-xs font-medium text-secondary">
            {isAnalyst ? "You" : "Agithar"}
          </span>
          <span className="font-mono text-[10px] text-dim">
            {formatTime(message.created_at)}
          </span>
        </div>

        {isAnalyst ? (
          <pre className="hud-corners overflow-x-auto whitespace-pre-wrap break-words border border-hairline bg-panel-2 p-3 font-mono text-sm text-secondary">
            {message.content}
          </pre>
        ) : (
          <StreamingText
            content={message.content}
            refs={message.evidence_refs}
            streaming={message.streaming}
            activeEvidenceId={activeEvidenceId}
            onHoverClaim={onHoverClaim}
          />
        )}
      </div>
    </div>
  );
}
