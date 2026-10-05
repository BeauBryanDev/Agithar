import { useEffect, useRef } from "react";
import type { AnalysisMessage } from "../../types/analysis";
import { MessageBubble } from "./MessageBubble";
import { EmptyState } from "../common/EmptyState";
import { Terminal } from "lucide-react";

interface ConversationThreadProps {
  messages: AnalysisMessage[];
  activeEvidenceId: string | null;
  onHoverClaim: (id: string | null) => void;
}

export function ConversationThread({
  messages,
  activeEvidenceId,
  onHoverClaim,
}: ConversationThreadProps) {
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages]);

  if (messages.length === 0) {
    return (
      <EmptyState
        icon={<Terminal className="h-8 w-8" strokeWidth={1.5} />}
        title="Ask Agithar about your shops"
        hint="For example: how is maisonroast doing? Who is scanning florabelle? Or paste a request or access-log lines and Agithar will explain what the sensors found."
      />
    );
  }

  return (
    <div className="flex flex-col gap-6 p-4">
      {messages.map((m) => (
        <MessageBubble
          key={m.id}
          message={m}
          activeEvidenceId={activeEvidenceId}
          onHoverClaim={onHoverClaim}
        />
      ))}
      <div ref={endRef} />
    </div>
  );
}
