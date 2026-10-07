import { useState, type KeyboardEvent } from "react";
import { Send, Square } from "lucide-react";
import { Button } from "../common/Button";

interface AnalysisInputProps {
  streaming: boolean;
  onSubmit: (value: string) => void;
  onCancel: () => void;
  /** Longest message the server accepts (the public demo has a short one). */
  maxChars?: number;
  placeholder?: string;
}

export function AnalysisInput({
  streaming,
  onSubmit,
  onCancel,
  maxChars,
  placeholder = "Ask Agithar about your shops, or paste a request or log lines…",
}: AnalysisInputProps) {
  const [value, setValue] = useState("");

  const submit = () => {
    const trimmed = value.trim();
    if (!trimmed || streaming) return;
    onSubmit(trimmed);
    setValue("");
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    // Enter sends, Shift+Enter adds a line; IME composition is left alone.
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      submit();
    }
  };

  return (
    <div className="border-t border-hairline bg-panel p-3">
      <div className="hud-corners relative border border-hairline bg-panel-2 transition-colors focus-within:border-electric">
        <textarea
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={onKeyDown}
          rows={3}
          maxLength={maxChars}
          placeholder={placeholder}
          className="w-full resize-none bg-transparent px-3 py-2.5 font-mono text-xs text-primary placeholder:text-dim focus:outline-none"
        />
        <div className="flex items-center justify-between border-t border-hairline px-3 py-2">
          <span className="font-mono text-[10px] text-dim">
            Enter to send · Shift + Enter for a new line
            {maxChars ? ` · ${value.length}/${maxChars}` : ""}
          </span>
          {streaming ? (
            <Button variant="danger" onClick={onCancel}>
              <Square className="h-3.5 w-3.5" /> Stop
            </Button>
          ) : (
            <Button variant="primary" onClick={submit} disabled={!value.trim()}>
              <Send className="h-3.5 w-3.5" /> Send
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
