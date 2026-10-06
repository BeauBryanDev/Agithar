import { useState } from "react";
import type { UserProfile } from "../../types/user";
import { formatDateTime } from "../../utils/formatters";

interface Props {
  users: UserProfile[];
  currentUserId: number;
  busyId: number | null;
  onToggle: (user: UserProfile) => void;
  onDelete: (user: UserProfile) => void;
}

export function UserTable({ users, currentUserId, busyId, onToggle, onDelete }: Props) {
  // Turning an account off asks once; turning it on does not.
  const [confirming, setConfirming] = useState<number | null>(null);
  // Deleting for good asks again, and only works on deactivated accounts.
  const [deleting, setDeleting] = useState<number | null>(null);

  if (users.length === 0) {
    return <p className="p-4 text-xs text-dim">No users.</p>;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse font-mono text-xs">
        <thead className="text-left text-dim">
          <tr>
            <th className="px-4 py-2 font-normal">user</th>
            <th className="px-3 py-2 font-normal">name</th>
            <th className="px-3 py-2 font-normal">email</th>
            <th className="px-3 py-2 font-normal">role</th>
            <th className="px-3 py-2 font-normal">status</th>
            <th className="px-3 py-2 font-normal">created</th>
            <th className="px-4 py-2 text-right font-normal">action</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => {
            const self = u.user_id === currentUserId;
            const working = busyId === u.user_id;
            return (
              <tr key={u.user_id} className="border-t border-hairline hover:bg-panel-2">
                <td className="px-4 py-2 text-primary">
                  {u.username}
                  {self && <span className="ml-2 text-[10px] text-dim">(you)</span>}
                </td>
                <td className="px-3 py-2 text-secondary">{u.name}</td>
                <td className="px-3 py-2 text-secondary">{u.email}</td>
                <td className={`px-3 py-2 ${u.is_admin ? "text-sev-high" : "text-electric"}`}>
                  {u.is_admin ? "admin" : "operator"}
                </td>
                <td className={`px-3 py-2 ${u.is_active ? "text-sev-low" : "text-dim"}`}>
                  {u.is_active ? "active" : "inactive"}
                </td>
                <td className="whitespace-nowrap px-3 py-2 text-dim">
                  {formatDateTime(u.created_at)}
                </td>
                <td className="px-4 py-2 text-right">
                  {self ? (
                    <span className="text-[10px] text-dim">use Profile</span>
                  ) : confirming === u.user_id ? (
                    <span className="inline-flex gap-2">
                      <button
                        disabled={working}
                        onClick={() => {
                          setConfirming(null);
                          onToggle(u);
                        }}
                        className="text-sev-critical hover:underline disabled:opacity-40"
                      >
                        confirm
                      </button>
                      <button onClick={() => setConfirming(null)} className="text-dim hover:text-primary">
                        cancel
                      </button>
                    </span>
                  ) : (
                    <span className="inline-flex gap-3">
                    <button
                      disabled={working}
                      onClick={() => (u.is_active ? setConfirming(u.user_id) : onToggle(u))}
                      className={`disabled:opacity-40 ${
                        u.is_active ? "text-sev-high hover:underline" : "text-electric hover:underline"
                      }`}
                    >
                      {working ? "…" : u.is_active ? "deactivate" : "activate"}
                    </button>
                    {!u.is_active &&
                      (deleting === u.user_id ? (
                        <span className="inline-flex gap-2">
                          <button
                            disabled={working}
                            onClick={() => {
                              setDeleting(null);
                              onDelete(u);
                            }}
                            className="text-sev-critical hover:underline disabled:opacity-40"
                          >
                            erase for good
                          </button>
                          <button onClick={() => setDeleting(null)} className="text-dim hover:text-primary">
                            cancel
                          </button>
                        </span>
                      ) : (
                        <button
                          disabled={working}
                          onClick={() => setDeleting(u.user_id)}
                          className="text-dim hover:text-sev-critical disabled:opacity-40"
                        >
                          delete
                        </button>
                      ))}
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
