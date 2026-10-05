import type { ReactNode } from "react";

interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  hint?: string;
  action?: ReactNode;
}

/** Empty states invite action rather than setting a mood. */
export function EmptyState({ icon, title, hint, action }: EmptyStateProps) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 px-6 py-12 text-center">
      {icon && <div className="text-dim">{icon}</div>}
      <p className="text-sm font-medium text-secondary">{title}</p>
      {hint && <p className="max-w-sm text-xs text-dim">{hint}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}
