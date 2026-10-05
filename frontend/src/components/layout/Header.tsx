import { Activity, Cpu, LogOut } from "lucide-react";

interface HeaderProps {
  detectorsActive: boolean;
  modelName: string;
  username: string;
  onSignOut: () => void;
}

export function Header({
  detectorsActive,
  modelName,
  username,
  onSignOut,
}: HeaderProps) {
  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-hairline bg-panel px-5">
      <div className="flex items-center gap-3">
        <span className="font-mono text-xs uppercase tracking-[0.2em] text-secondary">
          Blue-Team Analysis Console
        </span>
      </div>

      <div className="flex items-center gap-5">
        {/* Active model */}
        <div className="hidden items-center gap-2 sm:flex">
          <Cpu className="h-3.5 w-3.5 text-dim" strokeWidth={1.75} />
          <span className="font-mono text-xs text-secondary">
            model:{" "}
            <span className="text-electric">{modelName}</span>
          </span>
        </div>

        <span className="hidden h-4 w-px bg-hairline sm:block" />

        {/* Health readout */}
        <div className="flex items-center gap-2">
          <Activity className="h-3.5 w-3.5 text-dim" strokeWidth={1.75} />
          <span className="font-mono text-xs text-secondary">
            health <span className="text-sev-low">OK</span>
          </span>
        </div>

        <span className="h-4 w-px bg-hairline" />

        {/* Live indicator */}
        <div className="flex items-center gap-2">
          <span
            className={`h-2 w-2 rounded-full ${
              detectorsActive
                ? "aegis-live-dot bg-neon"
                : "bg-dim"
            }`}
          />
          <span className="font-mono text-[11px] uppercase tracking-wider text-secondary">
            {detectorsActive ? "Detectors active" : "Idle"}
          </span>
        </div>

        <span className="h-4 w-px bg-hairline" />

        {/* Signed-in user */}
        <div className="flex items-center gap-2">
          <span className="font-mono text-xs text-secondary">{username}</span>
          <button
            onClick={onSignOut}
            title="Sign out"
            className="text-dim transition-colors hover:text-primary"
          >
            <LogOut className="h-3.5 w-3.5" strokeWidth={1.75} />
          </button>
        </div>
      </div>
    </header>
  );
}
