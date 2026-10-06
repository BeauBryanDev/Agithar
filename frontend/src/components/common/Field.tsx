import type { InputHTMLAttributes } from "react";

interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string | null;
  hint?: string;
}

const input =
  "w-full border bg-panel-2 px-3 py-2 font-mono text-sm text-primary placeholder:text-dim focus:outline-none disabled:opacity-50";

/** A labelled input with an inline error, in the HUD style. */
export function Field({ label, error, hint, id, className = "", ...rest }: FieldProps) {
  const fieldId = id ?? `f-${label.toLowerCase().replace(/\s+/g, "-")}`;
  return (
    <div className="flex flex-col gap-1">
      <label
        htmlFor={fieldId}
        className="font-mono text-[10px] uppercase tracking-[0.2em] text-dim"
      >
        {label}
      </label>
      <input
        id={fieldId}
        aria-invalid={error ? true : undefined}
        className={`${input} ${
          error ? "border-sev-critical" : "border-hairline focus:border-electric"
        } ${className}`}
        {...rest}
      />
      {error ? (
        <span className="font-mono text-[11px] text-sev-critical">{error}</span>
      ) : hint ? (
        <span className="font-mono text-[10px] text-dim">{hint}</span>
      ) : null}
    </div>
  );
}
