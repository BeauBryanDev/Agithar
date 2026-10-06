import { Navigate, Outlet } from "react-router-dom";
import { useAuthStore } from "../../store/useAuthStore";

/** Admin-only routes. The server enforces this too; this only hides the page. */
export function RequireAdmin() {
  const user = useAuthStore((s) => s.user);
  if (!user?.is_admin) return <Navigate to="/console" replace />;
  return <Outlet />;
}
