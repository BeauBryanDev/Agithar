// The one and only axios instance. No other file may import axios.

import axios, { type AxiosInstance } from "axios";

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? "";
const LOGIN_PATH = "/users/login";
const UNAUTHORIZED = 401;

// The auth store registers itself here, so this file needs no store import.
let tokenProvider: () => string | null = () => null;
let unauthorizedHandler: () => void = () => {};

export function configureAuth(
  provider: () => string | null,
  onUnauthorized: () => void
): void {
  tokenProvider = provider;
  unauthorizedHandler = onUnauthorized;
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

apiClient.interceptors.request.use((config) => {
  const token = tokenProvider();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

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
    return Promise.reject(new Error(message));
  }
);
