import { useState } from "react";
import { Panel } from "../common/Panel";
import { Field } from "../common/Field";
import { Button } from "../common/Button";
import { deactivateMe } from "../../services/userService";
import { useAuthStore } from "../../store/useAuthStore";

export function DangerZone({ username }: { username: string }) {
  const signOut = useAuthStore((s) => s.signOut);
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const confirm = async () => {
    setBusy(true);
    setError(null);
    try {
      await deactivateMe();
      signOut();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not deactivate");
      setBusy(false);
    }
  };

  return (
    <Panel title="Deactivate account" bodyClassName="p-5">
      <p className="mb-3 max-w-xl text-xs leading-relaxed text-secondary">
        Deactivating signs you out and blocks this account. Nothing is erased:
        an admin can turn it back on.
      </p>
      {!open ? (
        <Button variant="danger" onClick={() => setOpen(true)}>
          Deactivate my account
        </Button>
      ) : (
        <div className="flex max-w-md flex-col gap-3">
          <Field
            label={`Type ${username} to confirm`}
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            autoComplete="off"
          />
          <div className="flex items-center gap-3">
            <Button variant="danger" disabled={busy || typed !== username} onClick={confirm}>
              {busy ? "Working…" : "Deactivate"}
            </Button>
            <Button variant="ghost" disabled={busy} onClick={() => { setOpen(false); setTyped(""); setError(null); }}>
              Cancel
            </Button>
          </div>
          {error && <span className="font-mono text-xs text-sev-critical">{error}</span>}
        </div>
      )}
    </Panel>
  );
}
