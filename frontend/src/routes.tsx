// Route table — one place, nothing else.

import { Navigate, type RouteObject } from "react-router-dom";
import { ConsoleLayout } from "./layouts/ConsoleLayout";
import { ConsolePage } from "./pages/ConsolePage";
import { DashboardPage } from "./pages/DashboardPage";
import { IncidentPage } from "./pages/IncidentPage";
import { FeedPage } from "./pages/FeedPage";
import { VulnLookupPage } from "./pages/VulnLookupPage";
import { IngestPage } from "./pages/IngestPage";
import { LoginPage } from "./pages/LoginPage";
import { SensorsPage } from "./pages/SensorsPage";
import { ProfilePage } from "./pages/ProfilePage";
import { UsersPage } from "./pages/UsersPage";
import { RequireAdmin } from "./components/auth/RequireAdmin";
import { RequireAuth } from "./components/auth/RequireAuth";

export const routes: RouteObject[] = [
  { path: "/login", element: <LoginPage /> },
  {
    element: <RequireAuth />,
    children: [
      {
        path: "/",
        element: <ConsoleLayout />,
        children: [
          { index: true, element: <Navigate to="/console" replace /> },
          { path: "console", element: <ConsolePage /> },
          { path: "dashboard", element: <DashboardPage /> },
          { path: "feed", element: <FeedPage /> },
          { path: "incidents/:caseKey", element: <IncidentPage /> },
          { path: "vuln", element: <VulnLookupPage /> },
          { path: "ingest", element: <IngestPage /> },
          { path: "sensors", element: <SensorsPage /> },
          { path: "profile", element: <ProfilePage /> },
          {
            element: <RequireAdmin />,
            children: [{ path: "users", element: <UsersPage /> }],
          },
          { path: "*", element: <Navigate to="/console" replace /> },
        ],
      },
    ],
  },
];
