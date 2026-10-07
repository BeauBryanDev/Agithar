import { NavLink } from "react-router-dom";
import adminIcon from "../../assets/admin.svg";
import { useAuthStore } from "../../store/useAuthStore";
import { ChevronLeft, Shield } from "lucide-react";
import { OPERATOR_NAV, type NavItem } from "./nav";

interface SidebarProps {
  collapsed: boolean;
  onToggle: () => void;
  /** Overrides the operator menu (the public demo passes its own). */
  items?: NavItem[];
}

function AdminIcon({ className }: { className?: string }) {
  return <img src={adminIcon} alt="" className={className} />;
}

const ADMIN_NAV: NavItem[] = [{ to: "/users", label: "Users", icon: AdminIcon }];

export function Sidebar({ collapsed, onToggle, items: given }: SidebarProps) {
  const isAdmin = useAuthStore((s) => s.user?.is_admin === true);
  const items: NavItem[] =
    given ?? (isAdmin ? [...OPERATOR_NAV, ...ADMIN_NAV] : OPERATOR_NAV);

  return (
    <aside
      className={`flex shrink-0 flex-col border-r border-hairline bg-panel transition-[width] duration-200 ${
        collapsed ? "w-16" : "w-56"
      }`}
    >
      <div className="flex h-14 items-center gap-2.5 border-b border-hairline px-4">
        <Shield className="h-6 w-6 shrink-0 text-neon" strokeWidth={1.75} />
        {!collapsed && (
          <div className="flex flex-col leading-tight">
            <span className="text-sm font-semibold tracking-wide text-primary">
              AEGIS
            </span>
            <span className="font-mono text-[9px] uppercase tracking-[0.25em] text-dim">
              CyberSec Guard
            </span>
          </div>
        )}
      </div>

      <nav className="flex flex-1 flex-col gap-1 p-2">
        {items.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `group relative flex items-center gap-3 rounded-sm px-3 py-2.5 text-sm transition-colors ${
                isActive
                  ? "bg-panel-2 text-primary"
                  : "text-secondary hover:bg-panel-2 hover:text-primary"
              }`
            }
          >
            {({ isActive }) => (
              <>
                {isActive && (
                  <span className="absolute left-0 top-1/2 h-6 -translate-y-1/2 border-l-2 border-electric" />
                )}
                <Icon
                  className={`h-[18px] w-[18px] shrink-0 ${
                    isActive ? "text-electric" : ""
                  }`}
                  strokeWidth={1.75}
                />
                {!collapsed && <span className="truncate">{label}</span>}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <button
        onClick={onToggle}
        className="flex h-11 items-center justify-center border-t border-hairline text-dim transition-colors hover:text-electric"
        aria-label="Toggle sidebar"
      >
        <ChevronLeft
          className={`h-4 w-4 transition-transform ${
            collapsed ? "rotate-180" : ""
          }`}
        />
      </button>
    </aside>
  );
}
