import { Outlet } from "react-router-dom";
import { Sidebar } from "../components/layout/Sidebar";
import { Header } from "../components/layout/Header";
import { useUIStore } from "../store/useUIStore";
import { useAuthStore } from "../store/useAuthStore";

const ACTIVE_MODEL = "aegis-verdict-8b";

export function ConsoleLayout() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  const toggle = useUIStore((s) => s.toggleSidebar);
  const detectorsActive = useUIStore((s) => s.detectorsActive);
  const user = useAuthStore((s) => s.user);
  const signOut = useAuthStore((s) => s.signOut);

  return (
    <div className="flex h-screen w-full overflow-hidden bg-void">
      <Sidebar collapsed={collapsed} onToggle={toggle} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Header
          detectorsActive={detectorsActive}
          modelName={ACTIVE_MODEL}
          username={user?.username ?? ""}
          onSignOut={signOut}
        />
        <main className="aegis-grid min-h-0 flex-1 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
