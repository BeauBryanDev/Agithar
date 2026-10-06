import { useCallback, useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import adminIcon from "../assets/admin.svg";
import { Panel } from "../components/common/Panel";
import { Button } from "../components/common/Button";
import { EmptyState } from "../components/common/EmptyState";
import { UserTable } from "../components/users/UserTable";
import { CreateUserForm } from "../components/users/CreateUserForm";
import { deleteUserPermanently, listUsers, setUserActive } from "../services/userService";
import { useAuthStore } from "../store/useAuthStore";
import type { UserList, UserProfile } from "../types/user";

const PAGE_SIZE = 20;

export function UsersPage() {
  const me = useAuthStore((s) => s.user);
  const [skip, setSkip] = useState(0);
  const [data, setData] = useState<UserList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await listUsers(skip, PAGE_SIZE));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Load failed");
    }
  }, [skip]);

  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (user: UserProfile) => {
    setBusyId(user.user_id);
    setActionError(null);
    try {
      await setUserActive(user.user_id, !user.is_active);
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Action failed");
    } finally {
      setBusyId(null);
    }
  };

  const erase = async (user: UserProfile) => {
    setBusyId(user.user_id);
    setActionError(null);
    try {
      await deleteUserPermanently(user.user_id);
      await load();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : "Delete failed");
    } finally {
      setBusyId(null);
    }
  };

  if (error && !data) {
    return (
      <EmptyState
        icon={<ShieldAlert className="h-8 w-8" strokeWidth={1.5} />}
        title="Could not load the users"
        hint={error}
      />
    );
  }
  if (!data || !me) {
    return <div className="p-4 font-mono text-xs text-dim">Loading users…</div>;
  }

  const first = data.total === 0 ? 0 : data.skip + 1;
  const last = Math.min(data.skip + data.limit, data.total);

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <img src={adminIcon} alt="" className="h-10 w-10" />
          <div>
          <h1 className="text-lg font-semibold text-primary">Users</h1>
          <p className="text-xs text-secondary">
            Accounts that can sign in to this console. Deactivating blocks an
            account without erasing it.
          </p>
          </div>
        </div>
      </div>

      <CreateUserForm
        onCreated={() => {
          setSkip(0);
          void load();
        }}
      />

      {actionError && (
        <p className="font-mono text-xs text-sev-critical">{actionError}</p>
      )}

      <Panel
        title={`Accounts · ${data.total}`}
        actions={
          <span className="font-mono text-[10px] text-dim">
            {first}-{last} of {data.total}
          </span>
        }
      >
        <UserTable
          users={data.items}
          currentUserId={me.user_id}
          busyId={busyId}
          onToggle={toggle}
          onDelete={erase}
        />
        <div className="flex items-center justify-between border-t border-hairline px-4 py-2">
          <Button variant="ghost" disabled={skip === 0} onClick={() => setSkip(Math.max(0, skip - PAGE_SIZE))}>
            Previous
          </Button>
          <Button variant="ghost" disabled={data.skip + data.limit >= data.total} onClick={() => setSkip(skip + PAGE_SIZE)}>
            Next
          </Button>
        </div>
      </Panel>
    </div>
  );
}
