import type { AuthKitConfig, AuthKitUser, TokenResponse } from "./types";

export async function exchangeCode(
  config: AuthKitConfig,
  params: { code: string; codeVerifier: string },
): Promise<TokenResponse> {
  const url = new URL("/user_management/authenticate", config.apiBaseUrl);

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: config.clientId,
    code: params.code,
    code_verifier: params.codeVerifier,
  });

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed (${response.status})`);
  }

  return response.json();
}

export function decodeJwtClaims(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");

    const json = atob(payload);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

export function extractUser(tokenResponse: TokenResponse): AuthKitUser {
  return {
    sub: tokenResponse.user.id,
    email: tokenResponse.user.email,
    firstName: tokenResponse.user.first_name ?? undefined,
    lastName: tokenResponse.user.last_name ?? undefined,
    profilePictureUrl: tokenResponse.user.profile_picture_url ?? undefined,
  };
}
