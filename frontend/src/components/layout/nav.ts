// The navigation of each layout. A page that is not listed here has no link.

import type { ComponentType } from "react";
import {
  Terminal,
  LayoutDashboard,
  ListFilter,
  ShieldAlert,
  Upload,
  UserCircle,
  Radar,
} from "lucide-react";

export type NavItem = {
  to: string;
  label: string;
  icon: ComponentType<{ className?: string; strokeWidth?: number }>;
};

export const OPERATOR_NAV: NavItem[] = [
  { to: "/console", label: "Console", icon: Terminal },
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/feed", label: "Detection Feed", icon: ListFilter },
  { to: "/sensors", label: "Sensors", icon: Radar },
  { to: "/vuln", label: "Vuln Lookup", icon: ShieldAlert },
  { to: "/ingest", label: "Ingest", icon: Upload },
  { to: "/profile", label: "Profile", icon: UserCircle },
];

// The public demo: four pages, nothing about the real deployment.
export const GUEST_NAV: NavItem[] = [
  { to: "/demo/console", label: "Console", icon: Terminal },
  { to: "/demo/sensors", label: "Sensors", icon: Radar },
  { to: "/demo/vuln", label: "Vuln Lookup", icon: ShieldAlert },
  { to: "/demo/ingest", label: "Ingest", icon: Upload },
];
