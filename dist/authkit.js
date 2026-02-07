"use strict";
(() => {
  // src/pkce.ts
  var PKCE_STORAGE_KEY = "authkit:pkce";
  var PKCE_MAX_AGE_MS = 10 * 60 * 1e3;
  function randomString(length) {
    const chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    const random = new Uint8Array(length);
    crypto.getRandomValues(random);
    return Array.from(random, (b) => chars[b % chars.length]).join("");
  }
  function base64UrlEncode(bytes) {
    let binary = "";
    for (const b of bytes) {
      binary += String.fromCharCode(b);
    }
    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  }
  async function createPkceBundle() {
    const codeVerifier = randomString(64);
    const state = randomString(32);
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(codeVerifier),
    );
    const codeChallenge = base64UrlEncode(new Uint8Array(digest));
    return { state, codeVerifier, codeChallenge };
  }
  function storePkce(bundle) {
    sessionStorage.setItem(
      PKCE_STORAGE_KEY,
      JSON.stringify({
        state: bundle.state,
        codeVerifier: bundle.codeVerifier,
        createdAt: Date.now(),
      }),
    );
  }
  function retrievePkce() {
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
  function clearPkce() {
    sessionStorage.removeItem(PKCE_STORAGE_KEY);
  }

  // src/urls.ts
  function createAuthorizeUrl(config, params) {
    const url = new URL("/user_management/authorize", config.apiBaseUrl);
    url.searchParams.set("client_id", config.clientId);
    url.searchParams.set("redirect_uri", config.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("code_challenge", params.codeChallenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("state", params.state);
    if (params.screenHint)
      url.searchParams.set("screen_hint", params.screenHint);
    if (params.loginHint) url.searchParams.set("login_hint", params.loginHint);
    if (params.organizationId)
      url.searchParams.set("organization_id", params.organizationId);
    if (params.invitationToken)
      url.searchParams.set("invitation_token", params.invitationToken);
    return url.toString();
  }
  function createLogoutUrl(config, sessionId, returnTo) {
    const url = new URL("/user_management/sessions/logout", config.apiBaseUrl);
    url.searchParams.set("session_id", sessionId);
    if (returnTo) url.searchParams.set("return_to", returnTo);
    return url.toString();
  }

  // src/token.ts
  async function exchangeCode(config, params) {
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
  function decodeJwtClaims(token) {
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
  function extractUser(tokenResponse) {
    return {
      sub: tokenResponse.user.id,
      email: tokenResponse.user.email,
      firstName: tokenResponse.user.first_name ?? void 0,
      lastName: tokenResponse.user.last_name ?? void 0,
      profilePictureUrl: tokenResponse.user.profile_picture_url ?? void 0,
    };
  }

  // src/session.ts
  var SESSION_KEY = "authkit:session";
  function storeSession(accessToken, user) {
    const session = { accessToken, user, storedAt: Date.now() };
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  }
  function getSession() {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }
  function clearSession() {
    localStorage.removeItem(SESSION_KEY);
  }

  // src/events.ts
  function dispatchAuthKitEvent(name, detail) {
    document.dispatchEvent(
      new CustomEvent(`authkit:${name}`, {
        detail,
        bubbles: true,
      }),
    );
  }

  // src/authkit.ts
  (function () {
    if (typeof window === "undefined") return;
    const scriptEl = document.currentScript;
    const dataset = scriptEl?.dataset ?? {};
    const clientId = dataset.clientId;
    if (!clientId) {
      console.error("[AuthKit] Missing required data-client-id attribute.");
      return;
    }
    const redirectUri = dataset.redirectUri || window.location.origin;
    const config = {
      clientId,
      redirectUri,
      apiBaseUrl: dataset.apiHostname
        ? `https://${dataset.apiHostname}`
        : "https://api.workos.com",
      devMode:
        dataset.devMode !== void 0
          ? dataset.devMode === "true"
          : location.hostname === "localhost" ||
            location.hostname === "127.0.0.1",
      autoCallback: dataset.autoCallback !== "false",
    };
    let currentUser = null;
    let currentAccessToken = null;
    const existingSession = getSession();
    if (existingSession) {
      currentUser = existingSession.user;
      currentAccessToken = existingSession.accessToken;
    }
    async function signIn(opts) {
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
    async function signUp(opts) {
      return signIn({ ...opts, screenHint: "sign-up" });
    }
    function signOut(opts) {
      dispatchAuthKitEvent("signed-out");
      const accessToken = currentAccessToken;
      clearSession();
      currentUser = null;
      currentAccessToken = null;
      if (accessToken) {
        const claims = decodeJwtClaims(accessToken);
        const sessionId = claims?.sid;
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
    function getUser() {
      return currentUser;
    }
    function getAccessToken() {
      return currentAccessToken;
    }
    async function handleCallback() {
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
    let resolveReady;
    const ready = new Promise((resolve) => {
      resolveReady = resolve;
    });
    const authkit = {
      ready,
      signIn,
      signUp,
      signOut,
      getUser,
      getAccessToken,
    };
    window.AuthKit = authkit;
    const isCallbackUrl = (function () {
      try {
        const redirectPath = new URL(redirectUri, window.location.origin)
          .pathname;
        const currentPath = window.location.pathname;
        return (
          (currentPath === redirectPath ||
            currentPath === redirectPath + "/") &&
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
      resolveReady({ user: currentUser });
      dispatchAuthKitEvent("ready", { user: currentUser });
    }
  })();
})();
//# sourceMappingURL=authkit.js.map
