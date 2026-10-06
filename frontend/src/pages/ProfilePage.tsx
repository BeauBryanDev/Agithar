import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { EmptyState } from "../components/common/EmptyState";
import { ProfileDetails } from "../components/profile/ProfileDetails";
import { ProfileEditForm } from "../components/profile/ProfileEditForm";
import { PasswordForm } from "../components/profile/PasswordForm";
import { DangerZone } from "../components/profile/DangerZone";
import { fetchProfile } from "../services/userService";
import type { UserProfile } from "../types/user";

export function ProfilePage() {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    fetchProfile()
      .then((p) => alive && setProfile(p))
      .catch((err) => {
        if (alive) setError(err instanceof Error ? err.message : "Load failed");
      });
    return () => {
      alive = false;
    };
  }, []);

  if (error) {
    return (
      <EmptyState
        icon={<ShieldAlert className="h-8 w-8" strokeWidth={1.5} />}
        title="Could not load your profile"
        hint={error}
      />
    );
  }
  if (!profile) {
    return <div className="p-4 font-mono text-xs text-dim">Loading profile…</div>;
  }

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-4 p-4">
      <h1 className="text-lg font-semibold text-primary">My profile</h1>
      <ProfileDetails profile={profile} />
      <ProfileEditForm profile={profile} onSaved={setProfile} />
      <PasswordForm />
      <DangerZone username={profile.username} />
    </div>
  );
}
