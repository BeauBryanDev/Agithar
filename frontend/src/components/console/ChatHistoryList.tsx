import { useState } from "react";
import { History, Trash2 } from "lucide-react";
import { Button } from "../common/Button";
import { EmptyState } from "../common/EmptyState";
import { formatDateTime } from "../../utils/formatters";
import { useChatHistory } from "../../hooks/useChatHistory";

interface ChatHistoryListProps {
  /** Called after a conversation was reopened, to go back to the thread. */
  onOpened: () => void;
}

/** The user's own past conversations. Titles are plain text, never HTML. */
export function ChatHistoryList({ onOpened }: ChatHistoryListProps) {
  const history = useChatHistory(true);
  const [confirmId, setConfirmId] = useState<string | null>(null);

  async function open(id: string) {
    if (await history.reopen(id)) onOpened();
  }

  if (!history.loading && history.items.length === 0 && !history.error) {
    return (
      <EmptyState
        icon={<History size={28} />}
        title="No saved conversations yet"
        hint="Every conversation you have with Agithar is kept here for 90 days."
      />
    );
  }

  return (
    <div className="flex flex-col gap-2 p-4">
      <p className="font-mono text-[11px] uppercase tracking-wider text-dim">
        {history.total} conversation{history.total === 1 ? "" : "s"} · kept 90
        days
      </p>

      {history.error && (
        <p className="rounded-sm border border-sev-critical/50 px-3 py-2 text-xs text-sev-critical">
          {history.error}
        </p>
      )}

      <ul className="flex flex-col gap-2">
        {history.items.map((item) => {
          const current = item.id === history.currentId;
          const busy = history.busyId === item.id;
          const confirming = confirmId === item.id;

          return (
            <li
              key={item.id}
              className={`hud-corners flex items-center gap-3 border px-3 py-2 ${
                current ? "border-electric" : "border-hairline"
              }`}
            >
              <button
                type="button"
                disabled={busy}
                onClick={() => void open(item.id)}
                className="min-w-0 flex-1 text-left disabled:opacity-50"
              >
                <span className="block truncate text-sm text-primary">
                  {item.title}
                </span>
                <span className="font-mono text-[11px] text-dim">
                  {formatDateTime(item.created_at)}
                  {current && " · open now"}
                </span>
              </button>

              {confirming ? (
                <span className="flex shrink-0 items-center gap-2">
                  <Button
                    variant="danger"
                    disabled={busy}
                    onClick={() => {
                      setConfirmId(null);
                      void history.remove(item.id);
                    }}
                  >
                    Delete
                  </Button>
                  <Button variant="ghost" onClick={() => setConfirmId(null)}>
                    Keep
                  </Button>
                </span>
              ) : (
                <button
                  type="button"
                  aria-label={`Delete conversation ${item.title}`}
                  title="Delete"
                  disabled={busy}
                  onClick={() => setConfirmId(item.id)}
                  className="shrink-0 p-1 text-dim hover:text-sev-critical disabled:opacity-50"
                >
                  <Trash2 size={16} />
                </button>
              )}
            </li>
          );
        })}
      </ul>

      {history.loading && (
        <p className="font-mono text-[11px] text-dim">Loading…</p>
      )}

      {history.hasMore && !history.loading && (
        <Button variant="ghost" onClick={() => void history.loadMore()}>
          Load more
        </Button>
      )}
    </div>
  );
}
