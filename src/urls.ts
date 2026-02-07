import type { AuthKitConfig } from "./types";

export function createAuthorizeUrl(
  config: AuthKitConfig,
  params: {
    codeChallenge: string;
    state: string;
    screenHint?: "sign-in" | "sign-up";
    loginHint?: string;
    organizationId?: string;
    invitationToken?: string;
  },
): string {
  const url = new URL("/user_management/authorize", config.apiBaseUrl);
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("code_challenge", params.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", params.state);
  if (params.screenHint) url.searchParams.set("screen_hint", params.screenHint);
  if (params.loginHint) url.searchParams.set("login_hint", params.loginHint);
  if (params.organizationId)
    url.searchParams.set("organization_id", params.organizationId);
  if (params.invitationToken)
    url.searchParams.set("invitation_token", params.invitationToken);
  return url.toString();
}

export function createLogoutUrl(
  config: AuthKitConfig,
  sessionId: string,
  returnTo?: string,
): string {
  const url = new URL("/user_management/sessions/logout", config.apiBaseUrl);
  url.searchParams.set("session_id", sessionId);
  if (returnTo) url.searchParams.set("return_to", returnTo);
  return url.toString();
}
