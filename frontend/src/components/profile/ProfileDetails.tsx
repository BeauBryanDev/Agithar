import { Panel } from "../common/Panel";
import dragon from "../../assets/dragon-avatar.webp";
import type { UserProfile } from "../../types/user";
import { formatDateTime } from "../../utils/formatters";

function Row({ label, value }: { label: string; value: string }) {
  return (
    <>
      <dt className="font-mono text-[10px] uppercase tracking-[0.2em] text-dim">
        {label}
      </dt>
      <dd className="break-all font-mono text-sm text-primary">{value}</dd>
    </>
  );
}

export function ProfileDetails({ profile }: { profile: UserProfile }) {
  return (
    <Panel title="Operator" bodyClassName="p-5">
      <div className="mb-5 flex flex-wrap items-center gap-4">
        <img
          src={dragon}
          alt=""
          width={96}
          height={96}
          className="hud-corners h-24 w-24 border border-hairline bg-panel-2 object-contain p-1"
        />
        <span className="font-mono text-lg font-semibold text-neon">
          {profile.username}
        </span>
        <span
          className={`rounded-sm border border-hairline bg-panel-2 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${
            profile.is_admin ? "text-sev-high" : "text-electric"
          }`}
        >
          {profile.is_admin ? "admin" : "operator"}
        </span>
        {!profile.is_active && (
          <span className="font-mono text-[10px] uppercase text-sev-critical">
            inactive
          </span>
        )}
      </div>
      <dl className="grid grid-cols-[8rem_1fr] gap-x-4 gap-y-2.5">
        <Row label="name" value={profile.name} />
        <Row label="email" value={profile.email} />
        <Row label="gender" value={profile.gender ?? "not set"} />
        <Row
          label="date of birth"
          value={profile.dob ? formatDateTime(profile.dob).slice(0, 10) : "not set"}
        />
        <Row label="member since" value={formatDateTime(profile.created_at)} />
        <Row label="last update" value={formatDateTime(profile.updated_at)} />
      </dl>
      <p className="mt-4 text-[11px] leading-relaxed text-dim">
        Name, username, email, date of birth and gender are fixed. Ask an admin
        if one of them is wrong.
      </p>
    </Panel>
  );
}
