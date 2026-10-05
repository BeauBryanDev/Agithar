import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { Panel } from "../components/common/Panel";
import { Button } from "../components/common/Button";
import { useAuthStore } from "../store/useAuthStore";

export function LoginPage() {
  const token = useAuthStore((s) => s.token);
  const user = useAuthStore((s) => s.user);
  const signIn = useAuthStore((s) => s.signIn);
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (token && user) return <Navigate to="/console" replace />;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await signIn(username.trim(), password);
      navigate("/console", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign in failed");
      setPassword("");
    } finally {
      setBusy(false);
    }
  };

  const field =
    "w-full border border-hairline bg-panel-2 px-3 py-2.5 font-mono text-sm text-primary placeholder:text-dim focus:border-electric focus:outline-none";

  return (
    <div className="aegis-grid flex h-screen items-center justify-center bg-void p-4">
      <div className="w-full max-w-sm">
        <Panel title="Aegis Cyber Guard — Sign in" bodyClassName="p-5">
          <form onSubmit={submit} className="flex flex-col gap-3">
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="username"
              autoComplete="username"
              autoFocus
              className={field}
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="password"
              autoComplete="current-password"
              className={field}
            />
            {error && (
              <p className="font-mono text-xs text-sev-critical">{error}</p>
            )}
            <Button type="submit" disabled={busy || !username || !password}>
              {busy ? "Signing in…" : "Sign in"}
            </Button>
          </form>
        </Panel>
      </div>
    </div>
  );
}
