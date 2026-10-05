import type { ReactNode } from "react";

interface PanelProps {
  children: ReactNode;
  title?: string;
  actions?: ReactNode;
  className?: string;
  bodyClassName?: string;
  /** Show HUD corner brackets. */
  corners?: boolean;
}

/** HUD-cornered panel wrapper. Structure through hairlines, not heavy boxes. */
export function Panel({
  children,
  title,
  actions,
  className = "",
  bodyClassName = "",
  corners = true,
}: PanelProps) {
  return (
    <section
      className={`relative border border-hairline bg-panel ${className}`}
    >
      {corners && (
        <>
          <span className="pointer-events-none absolute -left-px -top-px h-3 w-3 border-l border-t border-electric" />
          <span className="pointer-events-none absolute -right-px -top-px h-3 w-3 border-r border-t border-electric" />
          <span className="pointer-events-none absolute -bottom-px -left-px h-3 w-3 border-b border-l border-electric" />
          <span className="pointer-events-none absolute -bottom-px -right-px h-3 w-3 border-b border-r border-electric" />
        </>
      )}
      {(title || actions) && (
        <header className="flex items-center justify-between border-b border-hairline px-4 py-2.5">
          {title && (
            <h2 className="font-mono text-xs uppercase tracking-[0.18em] text-secondary">
              {title}
            </h2>
          )}
          {actions}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </section>
  );
}
