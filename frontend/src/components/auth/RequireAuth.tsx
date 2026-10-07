import { useEffect } from "react";
import { Navigate, Outlet } from "react-router-dom";
import { useAuthStore } from "../../store/useAuthStore";

/** Everything inside needs a signed-in user; otherwise go to the login. */
export function RequireAuth() {
  const token = useAuthStore((s) => s.token);
  const mode = useAuthStore((s) => s.mode);
  const user = useAuthStore((s) => s.user);
  const restore = useAuthStore((s) => s.restore);

  useEffect(() => {
    void restore();
  }, [restore, token]);

  if (!token) return <Navigate to="/login" replace />;
  // A guest never sees an operator page, not even for a moment.
  if (mode === "guest") return <Navigate to="/demo/console" replace />;

  if (!user) {
    return (
      <div className="flex h-screen items-center justify-center bg-void font-mono text-xs text-dim">
        Checking your session…
      </div>
    );
  }

  return <Outlet />;
}
