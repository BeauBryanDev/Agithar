import { Outlet, useNavigate } from "react-router-dom";
import { Sidebar } from "../components/layout/Sidebar";
import { Header } from "../components/layout/Header";
import { GUEST_NAV } from "../components/layout/nav";
import { useUIStore } from "../store/useUIStore";
import { useAuthStore } from "../store/useAuthStore";

/** The shell of the public demo: four pages, read-only, no account. */
export function PublicLayout() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  const toggle = useUIStore((s) => s.toggleSidebar);
  const detectorsActive = useUIStore((s) => s.detectorsActive);
  const signOut = useAuthStore((s) => s.signOut);
  const navigate = useNavigate();

  const leave = () => {
    signOut();
    navigate("/login", { replace: true });
  };

  return (
    <div className="flex h-screen w-full overflow-hidden bg-void">
      <Sidebar collapsed={collapsed} onToggle={toggle} items={GUEST_NAV} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Header
          guest
          detectorsActive={detectorsActive}
          username=""
          onSignOut={leave}
        />
        <main className="aegis-grid min-h-0 flex-1 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
