// The one and only axios instance. No other file may import axios.

import axios, { type AxiosInstance } from "axios";

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "";
const LOGIN_PATH = "/users/login";
const UNAUTHORIZED = 401;

// The auth store registers itself here, so this file needs no store import.
let tokenProvider: () => string | null = () => null;
let unauthorizedHandler: () => void = () => {};
let guestProvider: () => boolean = () => false;
let guestRenewer: () => Promise<string> = async () => "";

export function configureAuth(
  provider: () => string | null,
  onUnauthorized: () => void,
  isGuest: () => boolean = () => false,
  renewGuest: () => Promise<string> = async () => ""
): void {
  tokenProvider = provider;
  unauthorizedHandler = onUnauthorized;
  guestProvider = isGuest;
  guestRenewer = renewGuest;
}

/** True in the public demo. */
export function isGuestSession(): boolean {
  return guestProvider();
}

/** The public demo has its own read-only routes under /public. */
export function apiPath(path: string): string {
  return guestProvider() ? `/public${path}` : path;
}

/** For code that cannot use axios: the token was refused, sign out. */
export function reportUnauthorized(): void {
  unauthorizedHandler();
}

/** The Authorization header for code that cannot use axios (streaming fetch). */
export function authHeaders(): Record<string, string> {
  const token = tokenProvider();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export const apiClient: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30_000,
  headers: {
    "Content-Type": "application/json",
  },
});

const VISITORS_PATH = "/public/visitors";

apiClient.interceptors.request.use(async (config) => {
  // A guest token lasts 30 minutes: renew it before it runs out, so a page
  // that stays open never starts failing. (Minting one needs no token.)
  const minting = String(config.url ?? "").endsWith(VISITORS_PATH);
  const token =
    guestProvider() && !minting ? await guestRenewer() : tokenProvider();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

/** The HTTP status of a failed request, when there was one. */
export function errorStatus(err: unknown): number | null {
  const status = (err as { status?: unknown })?.status;
  return typeof status === "number" ? status : null;
}

/** FastAPI sends detail as a string, or as a list of {msg} for a 422. */
function describe(detail: unknown, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const messages = detail
      .map((d) => (d && typeof d === "object" ? (d as { msg?: string }).msg : null))
      .filter((m): m is string => typeof m === "string");
    if (messages.length > 0) return messages.join("; ");
  }
  return fallback;
}

// Response interceptor — normalize errors into the interface voice.
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status: number | undefined = error?.response?.status;
    const isLogin = String(error?.config?.url ?? "").endsWith(LOGIN_PATH);

    // An expired or missing token anywhere else sends the user to the login.
    if (status === UNAUTHORIZED && !isLogin) {
      unauthorizedHandler();
    }

    const message = describe(
      error?.response?.data?.detail,
      error?.message ?? "Unknown transport error"
    );
    return Promise.reject(Object.assign(new Error(message), { status }));
  }
);
