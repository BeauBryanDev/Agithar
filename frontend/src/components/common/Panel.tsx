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
          <span className="pointer-events-none absolute -left-0.5 -top-0.5 h-3.5 w-3.5 border-l-2 border-t-2 border-corner" />
          <span className="pointer-events-none absolute -right-0.5 -top-0.5 h-3.5 w-3.5 border-r-2 border-t-2 border-corner" />
          <span className="pointer-events-none absolute -bottom-0.5 -left-0.5 h-3.5 w-3.5 border-b-2 border-l-2 border-corner" />
          <span className="pointer-events-none absolute -bottom-0.5 -right-0.5 h-3.5 w-3.5 border-b-2 border-r-2 border-corner" />
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
