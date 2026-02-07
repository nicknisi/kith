import { describe, it, expect } from "vitest";
import { createAuthorizeUrl, createLogoutUrl } from "../urls";
import type { AuthKitConfig } from "../types";

const baseConfig: AuthKitConfig = {
  clientId: "client_test123",
  redirectUri: "https://example.com/callback",
  apiBaseUrl: "https://api.workos.com",
  devMode: false,
  autoCallback: true,
};

describe("createAuthorizeUrl", () => {
  it("includes all required params", () => {
    const url = createAuthorizeUrl(baseConfig, {
      codeChallenge: "test_challenge",
      state: "test_state",
    });

    const parsed = new URL(url);
    expect(parsed.origin).toBe("https://api.workos.com");
    expect(parsed.pathname).toBe("/user_management/authorize");
    expect(parsed.searchParams.get("client_id")).toBe("client_test123");
    expect(parsed.searchParams.get("redirect_uri")).toBe(
      "https://example.com/callback",
    );
    expect(parsed.searchParams.get("response_type")).toBe("code");
    expect(parsed.searchParams.get("code_challenge")).toBe("test_challenge");
    expect(parsed.searchParams.get("code_challenge_method")).toBe("S256");
    expect(parsed.searchParams.get("state")).toBe("test_state");
  });

  it("omits optional params when not provided", () => {
    const url = createAuthorizeUrl(baseConfig, {
      codeChallenge: "ch",
      state: "st",
    });

    const parsed = new URL(url);
    expect(parsed.searchParams.has("screen_hint")).toBe(false);
    expect(parsed.searchParams.has("login_hint")).toBe(false);
    expect(parsed.searchParams.has("organization_id")).toBe(false);
    expect(parsed.searchParams.has("invitation_token")).toBe(false);
  });

  it("includes optional params when provided", () => {
    const url = createAuthorizeUrl(baseConfig, {
      codeChallenge: "ch",
      state: "st",
      screenHint: "sign-up",
      loginHint: "user@example.com",
      organizationId: "org_123",
      invitationToken: "inv_456",
    });

    const parsed = new URL(url);
    expect(parsed.searchParams.get("screen_hint")).toBe("sign-up");
    expect(parsed.searchParams.get("login_hint")).toBe("user@example.com");
    expect(parsed.searchParams.get("organization_id")).toBe("org_123");
    expect(parsed.searchParams.get("invitation_token")).toBe("inv_456");
  });
});

describe("createLogoutUrl", () => {
  it("creates a logout URL with session_id", () => {
    const url = createLogoutUrl(baseConfig, "session_abc");
    const parsed = new URL(url);

    expect(parsed.pathname).toBe("/user_management/sessions/logout");
    expect(parsed.searchParams.get("session_id")).toBe("session_abc");
    expect(parsed.searchParams.has("return_to")).toBe(false);
  });

  it("includes return_to when provided", () => {
    const url = createLogoutUrl(
      baseConfig,
      "session_abc",
      "https://example.com",
    );
    const parsed = new URL(url);
    expect(parsed.searchParams.get("return_to")).toBe("https://example.com");
  });
});
