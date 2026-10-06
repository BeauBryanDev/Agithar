import { useEffect, useRef, useState, type FormEvent } from "react";
import { Panel } from "../common/Panel";
import { Field } from "../common/Field";
import { Button } from "../common/Button";
import { changePassword } from "../../services/userService";
import { useAuthStore } from "../../store/useAuthStore";
import { passwordProblem } from "../../utils/validation";

const SIGN_OUT_DELAY_MS = 2000;

export function PasswordForm() {
  const signOut = useAuthStore((s) => s.signOut);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const timer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    },
    []
  );

  const nextProblem = next ? passwordProblem(next) : null;
  const mismatch = confirm !== "" && confirm !== next ? "Passwords do not match." : null;
  const same = next !== "" && next === current ? "Choose a different password." : null;
  const ready = current !== "" && next !== "" && confirm === next && !nextProblem && !same;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    try {
      await changePassword(current, next);
      setDone(true);
      setCurrent("");
      setNext("");
      setConfirm("");
      // Sign in again with the new password.
      timer.current = window.setTimeout(signOut, SIGN_OUT_DELAY_MS);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not change the password");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="Change password" bodyClassName="p-5">
      {done ? (
        <p className="font-mono text-xs text-sev-low">
          Password changed. Signing you out so you can sign in again…
        </p>
      ) : (
        <form onSubmit={submit} className="flex max-w-md flex-col gap-4">
          <Field label="Current password" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" />
          <Field label="New password" type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" error={nextProblem ?? same} hint="12 to 72 characters." />
          <Field label="Repeat new password" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" error={mismatch} />
          <div className="flex items-center gap-3">
            <Button type="submit" disabled={busy || !ready}>
              {busy ? "Changing…" : "Change password"}
            </Button>
            {error && <span className="font-mono text-xs text-sev-critical">{error}</span>}
          </div>
        </form>
      )}
    </Panel>
  );
}
