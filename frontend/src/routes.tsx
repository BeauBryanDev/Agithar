// Route table — one place, nothing else.

import { Navigate, type RouteObject } from "react-router-dom";
import { ConsoleLayout } from "./layouts/ConsoleLayout";
import { ConsolePage } from "./pages/ConsolePage";
import { DashboardPage } from "./pages/DashboardPage";
import { FeedPage } from "./pages/FeedPage";
import { VulnLookupPage } from "./pages/VulnLookupPage";
import { IngestPage } from "./pages/IngestPage";
import { LoginPage } from "./pages/LoginPage";
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
          { path: "vuln", element: <VulnLookupPage /> },
          { path: "ingest", element: <IngestPage /> },
          { path: "*", element: <Navigate to="/console" replace /> },
        ],
      },
    ],
  },
];
