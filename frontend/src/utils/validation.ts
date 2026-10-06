// The same rules as the backend schemas (schemas/users.py). The server stays
// the judge; these only give an answer before the request is sent.

export const USERNAME = /^[A-Za-z0-9_.-]{3,32}$/;
export const EMAIL = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
export const PHONE = /^\+?[0-9]{7,15}$/;
export const PASSWORD_MIN = 12;
export const PASSWORD_MAX_BYTES = 72;

export function passwordProblem(value: string): string | null {
  if (value.length < PASSWORD_MIN) {
    return `Use at least ${PASSWORD_MIN} characters.`;
  }
  if (new TextEncoder().encode(value).length > PASSWORD_MAX_BYTES) {
    return `Use at most ${PASSWORD_MAX_BYTES} bytes.`;
  }
  return null;
}
