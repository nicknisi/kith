import type { AuthKitUser, StoredSession } from "./types";

const SESSION_KEY = "authkit:session";

export function storeSession(accessToken: string, user: AuthKitUser): void {
  const session: StoredSession = { accessToken, user, storedAt: Date.now() };
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function getSession(): StoredSession | null {
  const raw = localStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function clearSession(): void {
  localStorage.removeItem(SESSION_KEY);
}
