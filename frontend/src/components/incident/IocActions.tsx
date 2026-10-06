import { Panel } from "../common/Panel";
import type { ActionTaken, Ioc } from "../../types/incident";
import { formatDateTime } from "../../utils/formatters";

export function IocList({ iocs }: { iocs: Ioc[] }) {
  return (
    <Panel title="Indicators of compromise" bodyClassName="p-4">
      {iocs.length === 0 ? (
        <p className="text-xs text-dim">No indicators stored.</p>
      ) : (
        <ul className="flex flex-col divide-y divide-hairline">
          {iocs.map((i) => (
            <li key={i.ioc_id} className="flex items-baseline gap-3 py-1.5">
              <span className="w-20 shrink-0 font-mono text-[10px] uppercase tracking-wider text-dim">
                {i.ioc_type.replace("_", " ")}
              </span>
              <span className="min-w-0 break-all font-mono text-xs text-primary">
                {i.value}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function ActionList({ actions }: { actions: ActionTaken[] }) {
  return (
    <Panel title="Actions taken" bodyClassName="p-4">
      {actions.length === 0 ? (
        <p className="text-xs leading-relaxed text-dim">
          No actions recorded. Agithar is read-only: it recommends, the admin
          acts.
        </p>
      ) : (
        <ul className="flex flex-col divide-y divide-hairline">
          {actions.map((a) => (
            <li key={a.action_id} className="py-1.5 font-mono text-xs">
              <span className="text-primary">{a.tool_name}</span>
              <span className="ml-2 text-dim">
                by {a.performed_by} · {formatDateTime(a.created_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
