import type { PKCEBundle } from "./types";

const PKCE_STORAGE_KEY = "authkit:pkce";
const PKCE_MAX_AGE_MS = 10 * 60 * 1000; // 10 minutes

function randomString(length: number): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const random = new Uint8Array(length);
  crypto.getRandomValues(random);
  return Array.from(random, (b) => chars[b % chars.length]).join("");
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export async function createPkceBundle(): Promise<PKCEBundle> {
  const codeVerifier = randomString(64);
  const state = randomString(32);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(codeVerifier),
  );
  const codeChallenge = base64UrlEncode(new Uint8Array(digest));
  return { state, codeVerifier, codeChallenge };
}

export function storePkce(bundle: PKCEBundle): void {
  sessionStorage.setItem(
    PKCE_STORAGE_KEY,
    JSON.stringify({
      state: bundle.state,
      codeVerifier: bundle.codeVerifier,
      createdAt: Date.now(),
    }),
  );
}

export function retrievePkce(): {
  state: string;
  codeVerifier: string;
} | null {
  const raw = sessionStorage.getItem(PKCE_STORAGE_KEY);
  if (!raw) return null;

  try {
    const data = JSON.parse(raw);
    if (!data.state || !data.codeVerifier) return null;

    if (Date.now() - data.createdAt > PKCE_MAX_AGE_MS) {
      clearPkce();
      return null;
    }

    return { state: data.state, codeVerifier: data.codeVerifier };
  } catch {
    return null;
  }
}

export function clearPkce(): void {
  sessionStorage.removeItem(PKCE_STORAGE_KEY);
}
