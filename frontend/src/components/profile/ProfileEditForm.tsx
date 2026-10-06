import { useState, type FormEvent } from "react";
import { Panel } from "../common/Panel";
import { Field } from "../common/Field";
import { Button } from "../common/Button";
import { updateProfile } from "../../services/userService";
import type { ProfileChanges, UserProfile } from "../../types/user";
import { PHONE } from "../../utils/validation";

type Key = "phone_number" | "address" | "country" | "city";
const KEYS: Key[] = ["phone_number", "address", "country", "city"];

function initial(p: UserProfile): Record<Key, string> {
  return {
    phone_number: p.phone_number ?? "",
    address: p.address ?? "",
    country: p.country ?? "",
    city: p.city ?? "",
  };
}

interface Props {
  profile: UserProfile;
  onSaved: (p: UserProfile) => void;
}

export function ProfileEditForm({ profile, onSaved }: Props) {
  const [values, setValues] = useState(() => initial(profile));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const saved0 = initial(profile);
  const changed = KEYS.filter((k) => values[k].trim() !== saved0[k]);
  const phoneError =
    values.phone_number.trim() !== "" && !PHONE.test(values.phone_number.trim())
      ? "Use 7 to 15 digits, with an optional leading +."
      : null;

  const set = (k: Key) => (e: React.ChangeEvent<HTMLInputElement>) => {
    setValues((v) => ({ ...v, [k]: e.target.value }));
    setSaved(false);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (changed.length === 0 || phoneError) return;
    setBusy(true);
    setError(null);
    // Only what changed is sent; an emptied field becomes null.
    const changes: ProfileChanges = {};
    for (const k of changed) changes[k] = values[k].trim() || null;
    try {
      const next = await updateProfile(changes);
      onSaved(next);
      setValues(initial(next));
      setSaved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="Contact details" bodyClassName="p-5">
      <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2">
        <Field label="Phone" value={values.phone_number} onChange={set("phone_number")} placeholder="+573001234567" error={phoneError} autoComplete="tel" />
        <Field label="Country" value={values.country} onChange={set("country")} maxLength={100} autoComplete="country-name" />
        <Field label="City" value={values.city} onChange={set("city")} maxLength={100} autoComplete="address-level2" />
        <Field label="Address" value={values.address} onChange={set("address")} maxLength={255} autoComplete="street-address" />
        <div className="flex items-center gap-3 sm:col-span-2">
          <Button type="submit" disabled={busy || changed.length === 0 || !!phoneError}>
            {busy ? "Saving…" : "Save changes"}
          </Button>
          {saved && <span className="font-mono text-xs text-sev-low">Saved.</span>}
          {error && <span className="font-mono text-xs text-sev-critical">{error}</span>}
        </div>
      </form>
    </Panel>
  );
}
