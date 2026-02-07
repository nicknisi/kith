import { createPkceBundle, storePkce, retrievePkce, clearPkce } from "./pkce";
import { createAuthorizeUrl, createLogoutUrl } from "./urls";
import { exchangeCode, extractUser, decodeJwtClaims } from "./token";
import { storeSession, getSession, clearSession } from "./session";
import { dispatchAuthKitEvent } from "./events";
import type {
  AuthKitConfig,
  AuthKitUser,
  AuthKitGlobal,
  SignInOptions,
} from "./types";

(function () {
  if (typeof window === "undefined") return;

  const scriptEl = document.currentScript as HTMLScriptElement | null;
  const dataset = scriptEl?.dataset ?? {};

  const clientId = dataset.clientId;
  if (!clientId) {
    console.error("[AuthKit] Missing required data-client-id attribute.");
    return;
  }

  const redirectUri = dataset.redirectUri || window.location.origin;
  const config: AuthKitConfig = {
    clientId,
    redirectUri,
    apiBaseUrl: dataset.apiHostname
      ? `https://${dataset.apiHostname}`
      : "https://api.workos.com",
    devMode:
      dataset.devMode !== undefined
        ? dataset.devMode === "true"
        : location.hostname === "localhost" ||
          location.hostname === "127.0.0.1",
    autoCallback: dataset.autoCallback !== "false",
  };

  let currentUser: AuthKitUser | null = null;
  let currentAccessToken: string | null = null;

  const existingSession = getSession();
  if (existingSession) {
    currentUser = existingSession.user;
    currentAccessToken = existingSession.accessToken;
  }

  async function signIn(opts?: SignInOptions): Promise<void> {
    const bundle = await createPkceBundle();
    storePkce(bundle);

    const url = createAuthorizeUrl(config, {
      codeChallenge: bundle.codeChallenge,
      state: bundle.state,
      screenHint: opts?.screenHint,
      loginHint: opts?.loginHint,
      organizationId: opts?.organizationId,
      invitationToken: opts?.invitationToken,
    });

    if (opts?.state) {
      sessionStorage.setItem("authkit:state", JSON.stringify(opts.state));
    }

    window.location.assign(url);
  }

  async function signUp(
    opts?: Omit<SignInOptions, "screenHint">,
  ): Promise<void> {
    return signIn({ ...opts, screenHint: "sign-up" });
  }

  function signOut(opts?: { returnTo?: string }): void {
    dispatchAuthKitEvent("signed-out");

    const accessToken = currentAccessToken;
    clearSession();
    currentUser = null;
    currentAccessToken = null;

    if (accessToken) {
      const claims = decodeJwtClaims(accessToken);
      const sessionId = claims?.sid as string | undefined;
      if (sessionId) {
        const url = createLogoutUrl(config, sessionId, opts?.returnTo);
        window.location.assign(url);
        return;
      }
    }

    if (opts?.returnTo) {
      window.location.assign(opts.returnTo);
    } else {
      window.location.reload();
    }
  }

  function getUser(): AuthKitUser | null {
    return currentUser;
  }

  function getAccessToken(): string | null {
    return currentAccessToken;
  }

  async function handleCallback(): Promise<void> {
    const url = new URL(window.location.href);
    const code = url.searchParams.get("code");
    const stateParam = url.searchParams.get("state");

    if (!code) return;

    const pkce = retrievePkce();
    if (!pkce) {
      console.error(
        "[AuthKit] Missing PKCE verifier. Was sign-in started from this browser?",
      );
      return;
    }

    if (pkce.state !== stateParam) {
      console.error("[AuthKit] State mismatch in callback.");
      clearPkce();
      return;
    }

    try {
      const tokenResponse = await exchangeCode(config, {
        code,
        codeVerifier: pkce.codeVerifier,
      });

      const user = extractUser(tokenResponse);
      currentUser = user;
      currentAccessToken = tokenResponse.access_token;
      storeSession(tokenResponse.access_token, user);
      clearPkce();

      const cleanUrl = new URL(window.location.href);
      cleanUrl.search = "";
      history.replaceState({}, "", cleanUrl.toString());

      dispatchAuthKitEvent("signed-in", { user });
    } catch (error) {
      console.error("[AuthKit] Token exchange failed:", error);
      clearPkce();
    }
  }

  let resolveReady: (value: { user: AuthKitUser | null }) => void;
  const ready = new Promise<{ user: AuthKitUser | null }>((resolve) => {
    resolveReady = resolve;
  });

  const authkit: AuthKitGlobal = {
    ready,
    signIn,
    signUp,
    signOut,
    getUser,
    getAccessToken,
  };

  (window as any).AuthKit = authkit;

  const isCallbackUrl = (function () {
    try {
      const redirectPath = new URL(redirectUri, window.location.origin)
        .pathname;
      const currentPath = window.location.pathname;
      return (
        (currentPath === redirectPath || currentPath === redirectPath + "/") &&
        new URLSearchParams(window.location.search).has("code")
      );
    } catch {
      return false;
    }
  })();

  if (config.autoCallback && isCallbackUrl) {
    handleCallback()
      .then(() => {
        resolveReady({ user: currentUser });
        dispatchAuthKitEvent("ready", { user: currentUser });
      })
      .catch((error) => {
        console.error("[AuthKit] Callback handling failed:", error);
        resolveReady({ user: null });
        dispatchAuthKitEvent("ready", { user: null });
      });
  } else {
    resolveReady!({ user: currentUser });
    dispatchAuthKitEvent("ready", { user: currentUser });
  }
})();
