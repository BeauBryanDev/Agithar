import type { SeverityLevel } from "../../types/vulnerability";
import { severityTextClass, severityBgClass } from "../../utils/severity";

interface BadgeProps {
  level: SeverityLevel;
  label?: string;
}

/** Severity badge with a left-edge accent dot. Warm color used only here. */
export function Badge({ level, label }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-sm border border-hairline bg-panel-2 px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider ${severityTextClass(
        level
      )}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${severityBgClass(level)}`} />
      {label ?? level}
    </span>
  );
}
