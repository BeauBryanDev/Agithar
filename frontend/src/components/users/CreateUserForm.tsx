import { useState, type FormEvent } from "react";
import { Panel } from "../common/Panel";
import { Field } from "../common/Field";
import { Button } from "../common/Button";
import { createUser } from "../../services/userService";
import type { Gender, NewUser, UserProfile } from "../../types/user";
import { EMAIL, PHONE, USERNAME, passwordProblem } from "../../utils/validation";

const EMPTY = {
  name: "", username: "", email: "", password: "",
  phone: "", address: "", country: "", city: "", gender: "", dob: "", role: "operator",
};

export function CreateUserForm({ onCreated }: { onCreated: (u: UserProfile) => void }) {
  const [open, setOpen] = useState(false);
  const [v, setV] = useState(EMPTY);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  const set = (k: keyof typeof EMPTY) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => {
    setV((s) => ({ ...s, [k]: e.target.value }));
    setOk(null);
  };

  const errors = {
    name: v.name.trim() === "" ? "Required." : null,
    username: v.username !== "" && !USERNAME.test(v.username) ? "3 to 32 letters, digits, . _ -" : v.username === "" ? "Required." : null,
    email: v.email !== "" && !EMAIL.test(v.email.trim()) ? "Not a valid email." : v.email === "" ? "Required." : null,
    password: v.password === "" ? "Required." : passwordProblem(v.password),
    phone: v.phone !== "" && !PHONE.test(v.phone.trim()) ? "7 to 15 digits, optional +." : null,
    dob: v.dob !== "" && new Date(v.dob) > new Date() ? "Cannot be in the future." : null,
  };
  const valid = Object.values(errors).every((e) => e === null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError(null);
    const body: NewUser = {
      name: v.name.trim(),
      username: v.username,
      email: v.email.trim(),
      password: v.password,
      phone_number: v.phone.trim() || null,
      address: v.address.trim() || null,
      country: v.country.trim() || null,
      city: v.city.trim() || null,
      gender: (v.gender || null) as Gender | null,
      dob: v.dob ? `${v.dob}T00:00:00Z` : null,
      is_admin: v.role === "admin",
    };
    try {
      const created = await createUser(body);
      onCreated(created);
      setOk(`Created ${created.username}.`);
      setV(EMPTY);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the user");
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <Button onClick={() => setOpen(true)}>New user</Button>
    );
  }

  return (
    <Panel
      title="New user"
      bodyClassName="p-5"
      actions={
        <button onClick={() => setOpen(false)} className="font-mono text-[10px] uppercase tracking-wider text-dim hover:text-primary">
          close
        </button>
      }
    >
      <form onSubmit={submit} className="grid gap-4 sm:grid-cols-2">
        <Field label="Name" value={v.name} onChange={set("name")} maxLength={100} error={v.name ? null : undefined} />
        <Field label="Username" value={v.username} onChange={set("username")} autoComplete="off" error={v.username ? errors.username : null} />
        <Field label="Email" type="email" value={v.email} onChange={set("email")} autoComplete="off" error={v.email ? errors.email : null} />
        <Field label="Temporary password" type="password" value={v.password} onChange={set("password")} autoComplete="new-password" error={v.password ? errors.password : null} hint="12 to 72 characters. Share it safely; the user can change it in Profile." />
        <Field label="Phone" value={v.phone} onChange={set("phone")} error={errors.phone} />
        <Field label="Country" value={v.country} onChange={set("country")} maxLength={100} />
        <Field label="City" value={v.city} onChange={set("city")} maxLength={100} />
        <Field label="Address" value={v.address} onChange={set("address")} maxLength={255} />
        <div className="flex flex-col gap-1">
          <label htmlFor="f-gender" className="font-mono text-[10px] uppercase tracking-[0.2em] text-dim">Gender</label>
          <select id="f-gender" value={v.gender} onChange={set("gender")} className="w-full border border-hairline bg-panel-2 px-3 py-2 font-mono text-sm text-primary focus:border-electric focus:outline-none">
            <option value="">not set</option>
            <option value="male">male</option>
            <option value="female">female</option>
            <option value="other">other</option>
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="f-role" className="font-mono text-[10px] uppercase tracking-[0.2em] text-dim">Role</label>
          <select id="f-role" value={v.role} onChange={set("role")} className="w-full border border-hairline bg-panel-2 px-3 py-2 font-mono text-sm text-primary focus:border-electric focus:outline-none">
            <option value="operator">operator (read and chat)</option>
            <option value="admin">admin (full control)</option>
          </select>
        </div>
        <Field label="Date of birth" type="date" value={v.dob} onChange={set("dob")} error={errors.dob} />
        <div className="flex flex-wrap items-center gap-3 sm:col-span-2">
          <Button type="submit" disabled={busy || !valid}>
            {busy ? "Creating…" : "Create user"}
          </Button>
          <span className="text-[11px] text-dim">{v.role === "admin" ? "Admins can create and remove users and push events. Grant it sparingly." : "Operators can view everything and chat, but cannot manage users."}</span>
          {ok && <span className="font-mono text-xs text-sev-low">{ok}</span>}
          {error && <span className="font-mono text-xs text-sev-critical">{error}</span>}
        </div>
      </form>
    </Panel>
  );
}
