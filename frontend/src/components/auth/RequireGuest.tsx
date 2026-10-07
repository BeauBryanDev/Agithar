import { Navigate, Outlet } from "react-router-dom";
import { useAuthStore } from "../../store/useAuthStore";

/** The public demo. Only a guest session gets in; a signed-in operator goes
 *  to the real console and everyone else to the login. The server enforces
 *  the real limits: this only decides which pages are shown. */
export function RequireGuest() {
  const token = useAuthStore((s) => s.token);
  const mode = useAuthStore((s) => s.mode);

  if (!token) return <Navigate to="/login" replace />;
  if (mode !== "guest") return <Navigate to="/console" replace />;
  return <Outlet />;
}
