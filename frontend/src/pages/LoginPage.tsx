import { useState, type FormEvent } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { Panel } from "../components/common/Panel";
import logo from "../assets/cybersoc-logo.webp";
import { Button } from "../components/common/Button";
import { useAuthStore } from "../store/useAuthStore";

export function LoginPage() {
  const token = useAuthStore((s) => s.token);
  const user = useAuthStore((s) => s.user);
  const mode = useAuthStore((s) => s.mode);
  const signIn = useAuthStore((s) => s.signIn);
  const enterAsGuest = useAuthStore((s) => s.enterAsGuest);
  const navigate = useNavigate();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (token && mode === "guest") return <Navigate to="/demo/console" replace />;
  if (token && user) return <Navigate to="/console" replace />;

  const guest = async () => {
    setBusy(true);
    setError(null);
    try {
      await enterAsGuest();
      navigate("/demo/console", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "The demo is unavailable");
    } finally {
      setBusy(false);
    }
  };

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
    <div className="aegis-grid flex min-h-screen items-center justify-center bg-void p-4">
      <div className="aegis-fade-in w-full max-w-sm">
        <div className="mb-4 flex flex-col items-center text-center">
          <img
            src={logo}
            alt="Aegis Cyber SOC"
            width={640}
            height={616}
            className="h-[min(40vh,22rem)] w-auto drop-shadow-[0_0_36px_rgba(46,155,255,0.55)]"
          />
          <h1 className="mt-4 font-mono text-xl font-semibold tracking-[0.3em] text-neon">
            AEGIS-CYBER-SOC
          </h1>
          <p className="mt-1 font-mono text-[10px] uppercase tracking-[0.25em] text-dim">
            Secure operator console
          </p>
        </div>
        <Panel title="Operator sign in" bodyClassName="p-5">
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
          <div className="mt-4 border-t border-hairline pt-4">
            <Button
              type="button"
              variant="ghost"
              className="w-full"
              disabled={busy}
              onClick={guest}
            >
              Enter as guest
            </Button>
            <p className="mt-2 text-center font-mono text-[10px] text-dim">
              Public demo: read-only, no account needed.
            </p>
          </div>
        </Panel>
      </div>
    </div>
  );
}
