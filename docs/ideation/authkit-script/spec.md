# Implementation Spec: AuthKit Script Tag

**Contract**: ./contract.md
**Estimated Effort**: M

## Technical Approach

Build a standalone IIFE script modeled directly on shoo.js's architecture but targeting WorkOS API endpoints. The script is a single self-executing function that:

1. Reads configuration from `document.currentScript.dataset`
2. Implements PKCE (code verifier + S256 challenge) using Web Crypto API
3. Constructs authorization URLs for WorkOS `/user_management/authorize`
4. Exchanges authorization codes via `POST /user_management/authenticate`
5. Decodes JWT access tokens to extract user claims (no signature verification)
6. Stores session data in localStorage
7. Auto-detects and processes OAuth callbacks
8. Exposes `window.AuthKit` with methods and a `ready` promise

The implementation follows shoo.js's patterns closely: IIFE wrapper, `document.currentScript` for config, `sessionStorage` for PKCE state, `localStorage` for session persistence. The key differences are the WorkOS-specific endpoints, the richer user object from WorkOS JWTs, and the addition of a `ready` promise + custom DOM events.

TypeScript source with tsup building to a single IIFE file. No runtime dependencies.

## File Changes

### New Files

| File Path                       | Purpose                                                                |
| ------------------------------- | ---------------------------------------------------------------------- |
| `package.json`                  | Project metadata, build scripts, dev dependencies only                 |
| `tsconfig.json`                 | TypeScript config targeting ES2020 with DOM lib                        |
| `tsup.config.ts`                | Build config producing single IIFE bundle                              |
| `src/authkit.ts`                | Main entry — IIFE bootstrap, config parsing, `window.AuthKit` exposure |
| `src/pkce.ts`                   | PKCE code verifier + S256 challenge generation                         |
| `src/urls.ts`                   | Authorization URL + logout URL construction                            |
| `src/token.ts`                  | Code exchange via fetch, JWT decoding                                  |
| `src/session.ts`                | localStorage session persistence (store/get/clear identity)            |
| `src/events.ts`                 | Custom DOM event dispatch helpers                                      |
| `src/types.ts`                  | Shared TypeScript interfaces                                           |
| `src/__tests__/pkce.test.ts`    | PKCE generation tests                                                  |
| `src/__tests__/urls.test.ts`    | URL construction tests                                                 |
| `src/__tests__/token.test.ts`   | JWT decoding tests                                                     |
| `src/__tests__/session.test.ts` | Session storage tests                                                  |
| `src/__tests__/authkit.test.ts` | Integration: bootstrap, config parsing, event dispatch                 |

## Implementation Details

### 1. Types (`src/types.ts`)

**Overview**: Shared interfaces used across modules.

```typescript
export interface AuthKitConfig {
  clientId: string;
  redirectUri: string;
  apiBaseUrl: string;
  devMode: boolean;
  autoCallback: boolean;
}

export interface PKCEBundle {
  state: string;
  codeVerifier: string;
  codeChallenge: string;
}

export interface AuthKitUser {
  sub: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  profilePictureUrl?: string;
  organizationId?: string;
  [key: string]: unknown;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  user: {
    id: string;
    email: string;
    first_name: string | null;
    last_name: string | null;
    email_verified: boolean;
    profile_picture_url: string | null;
    created_at: string;
    updated_at: string;
  };
  authentication_method?: string;
}

export interface StoredSession {
  accessToken: string;
  user: AuthKitUser;
  storedAt: number;
}

export interface AuthKitGlobal {
  ready: Promise<{ user: AuthKitUser | null }>;
  signIn(opts?: SignInOptions): Promise<void>;
  signUp(opts?: SignInOptions): Promise<void>;
  signOut(opts?: { returnTo?: string }): void;
  getUser(): AuthKitUser | null;
  getAccessToken(): string | null;
}

export interface SignInOptions {
  loginHint?: string;
  organizationId?: string;
  invitationToken?: string;
  state?: Record<string, unknown>;
  screenHint?: "sign-in" | "sign-up";
}
```

### 2. PKCE Module (`src/pkce.ts`)

**Pattern to follow**: shoo.js `createPkceBundle()` + authkit-js `src/utils/pkce.ts`

**Overview**: Generates PKCE code verifier and S256 challenge using Web Crypto API. Stores/retrieves PKCE state in sessionStorage.

```typescript
const PKCE_STORAGE_KEY = "authkit:pkce";

function randomString(length: number): string {
  // RFC 7636 unreserved characters
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
  const random = new Uint8Array(length);
  crypto.getRandomValues(random);
  return Array.from(random, (b) => chars[b % chars.length]).join("");
}

function base64UrlEncode(bytes: Uint8Array): string {
  /* ... */
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

export function retrievePkce(): { state: string; codeVerifier: string } | null {
  // Retrieve + validate + check 10-min expiry
}

export function clearPkce(): void {
  sessionStorage.removeItem(PKCE_STORAGE_KEY);
}
```

**Key decisions**:

- 64-char code verifier (matches authkit-js length, exceeds RFC 7636 minimum of 43)
- 32-char state parameter (matches shoo.js)
- 10-minute PKCE expiry (matches shoo.js `pkceMaxAgeMs`)
- sessionStorage for PKCE (transient, cleared on tab close)

**Implementation steps**:

1. Implement `randomString()` using `crypto.getRandomValues()`
2. Implement `base64UrlEncode()` — btoa + replace `+/=` chars
3. Implement `createPkceBundle()` using `crypto.subtle.digest("SHA-256", ...)`
4. Implement `storePkce()` / `retrievePkce()` / `clearPkce()` with sessionStorage
5. Add 10-minute expiry check in `retrievePkce()`

### 3. URL Construction (`src/urls.ts`)

**Pattern to follow**: shoo.js `createSignInUrl()` + authkit-js `HttpClient.getAuthorizationUrl()`

**Overview**: Builds WorkOS authorization and logout URLs with correct query parameters.

```typescript
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
```

**Key decisions**:

- Endpoint paths match WorkOS API: `/user_management/authorize`, `/user_management/sessions/logout`
- `response_type=code` is always set (OAuth 2.0 authorization code flow)
- `provider` param is NOT set — WorkOS AuthKit uses the hosted UI which handles provider selection
- State is passed as-is (consumer-provided state is JSON-stringified at the signIn level)

**Implementation steps**:

1. Implement `createAuthorizeUrl()` matching WorkOS query param names
2. Implement `createLogoutUrl()` for sign-out redirect
3. Verify param names against workos-node serializers (`get-authorization-url-options.serializer.ts`)

### 4. Token Exchange & JWT Decoding (`src/token.ts`)

**Pattern to follow**: shoo.js `exchangeCode()` + `decodeIdentityClaims()`, authkit-js `HttpClient.authenticateWithCode()`

**Overview**: Exchanges authorization code for tokens via POST, decodes JWT to extract user claims.

```typescript
export async function exchangeCode(
  config: AuthKitConfig,
  params: {
    code: string;
    codeVerifier: string;
  },
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
  // Base64url decode the payload (second segment)
  // No signature verification — same pattern as authkit-js and shoo.js
}

export function extractUser(tokenResponse: TokenResponse): AuthKitUser {
  // Map WorkOS user response to AuthKitUser shape
  return {
    sub: tokenResponse.user.id,
    email: tokenResponse.user.email,
    firstName: tokenResponse.user.first_name ?? undefined,
    lastName: tokenResponse.user.last_name ?? undefined,
    profilePictureUrl: tokenResponse.user.profile_picture_url ?? undefined,
  };
}
```

**Key decisions**:

- Uses `URLSearchParams` body (form-encoded), not JSON — matches OAuth 2.0 spec and what WorkOS expects
- No `client_secret` — this is a public client using PKCE only
- User data extracted from the response `user` object, not from the JWT claims — WorkOS returns a rich `user` object in the authenticate response
- JWT decoding available for consumers who want claims (e.g., `sid`, `org_id`, `exp`)

**Implementation steps**:

1. Implement `exchangeCode()` with fetch POST to `/user_management/authenticate`
2. Implement `decodeJwtClaims()` — split on `.`, base64url-decode segment [1], JSON.parse
3. Implement `extractUser()` mapping WorkOS response shape to `AuthKitUser`

### 5. Session Storage (`src/session.ts`)

**Pattern to follow**: shoo.js `persistIdentity()` / `getIdentity()` / `clearIdentity()`

**Overview**: Persists access token + user to localStorage. Simple get/set/clear.

```typescript
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
```

**Key decisions**:

- localStorage (not memory) — this is a script tag for static sites, sessions should survive page reloads
- No refresh token storage in v1 — refresh tokens require cookie-based flow which is out of scope
- `storedAt` timestamp for potential future expiry checks
- Access token stored alongside user — consumers can use it for API calls

**Implementation steps**:

1. Implement `storeSession()` — JSON stringify to localStorage
2. Implement `getSession()` — parse with error handling
3. Implement `clearSession()` — remove key

### 6. Event Helpers (`src/events.ts`)

**Overview**: Thin wrappers for dispatching custom events on `document`.

```typescript
export function dispatchAuthKitEvent(name: string, detail?: unknown): void {
  document.dispatchEvent(
    new CustomEvent(`authkit:${name}`, {
      detail,
      bubbles: true,
    }),
  );
}
```

Events dispatched:

- `authkit:ready` — `{ detail: { user: AuthKitUser | null } }` — after initialization
- `authkit:signed-in` — `{ detail: { user: AuthKitUser } }` — after successful code exchange
- `authkit:signed-out` — no detail — before sign-out redirect

### 7. Main Entry Point (`src/authkit.ts`)

**Pattern to follow**: shoo.js IIFE structure — the overall self-executing pattern, `document.currentScript` config reading, auto-callback bootstrap.

**Overview**: The orchestrator. Reads config, initializes, handles callbacks, exposes `window.AuthKit`.

```typescript
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

  // --- Config parsing ---
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

  // --- State ---
  let currentUser: AuthKitUser | null = null;
  let currentAccessToken: string | null = null;

  // Load existing session from localStorage
  const existingSession = getSession();
  if (existingSession) {
    currentUser = existingSession.user;
    currentAccessToken = existingSession.accessToken;
  }

  // --- Core methods ---
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

    // Store consumer state in sessionStorage if provided
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

    // Fallback: no session ID, just redirect to returnTo or reload
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

  // --- Callback handling ---
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

      // Clean URL
      const cleanUrl = new URL(window.location.href);
      cleanUrl.search = "";
      history.replaceState({}, "", cleanUrl.toString());

      dispatchAuthKitEvent("signed-in", { user });
    } catch (error) {
      console.error("[AuthKit] Token exchange failed:", error);
      clearPkce();
    }
  }

  // --- Ready promise ---
  let resolveReady: (value: { user: AuthKitUser | null }) => void;
  const ready = new Promise<{ user: AuthKitUser | null }>((resolve) => {
    resolveReady = resolve;
  });

  // --- Bootstrap ---
  const authkit: AuthKitGlobal = {
    ready,
    signIn,
    signUp,
    signOut,
    getUser,
    getAccessToken,
  };

  (window as any).AuthKit = authkit;

  // Auto-handle callback if on the redirect URI path
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
    // No callback — resolve immediately with existing session (or null)
    resolveReady!({ user: currentUser });
    dispatchAuthKitEvent("ready", { user: currentUser });
  }
})();
```

**Key decisions**:

- **Synchronous `getUser()` and `getAccessToken()`**: Return from in-memory state, populated from localStorage on load. No promises needed for reads.
- **No proxy layer needed**: Unlike the authkit-js wrapper approach, methods are defined upfront. `signIn`/`signUp` are self-contained async functions. Only `ready` is needed for timing.
- **State stored in sessionStorage**: Consumer-provided `state` object is stored separately and retrievable after callback (for custom post-login routing).
- **URL cleaning**: After callback, remove `code` and `state` from URL via `history.replaceState` — matches both authkit-js and shoo.js behavior.
- **`apiBaseUrl` constructed from hostname**: `data-api-hostname="api.workos.com"` becomes `https://api.workos.com`. Always HTTPS.

**Implementation steps**:

1. Parse `document.currentScript.dataset` into `AuthKitConfig`
2. Load existing session from localStorage
3. Define `signIn`, `signUp`, `signOut`, `getUser`, `getAccessToken`
4. Implement `handleCallback()` — PKCE validation + code exchange + session storage
5. Create `ready` promise
6. Assign `window.AuthKit`
7. Auto-detect callback URL and bootstrap
8. Resolve `ready` and dispatch `authkit:ready`

### 8. Project Scaffolding

**`package.json`**:

```json
{
  "name": "authkit-script",
  "version": "0.1.0",
  "private": true,
  "scripts": {
    "build": "tsup",
    "test": "jest",
    "format": "prettier --write .",
    "format:check": "prettier --check ."
  },
  "devDependencies": {
    "tsup": "^8.1.2",
    "typescript": "^5.5.3",
    "jest": "^29.7.0",
    "ts-jest": "^29.2.5",
    "@types/jest": "^29.5.14",
    "jest-environment-jsdom": "^29.7.0",
    "prettier": "^3.3.3"
  }
}
```

**`tsup.config.ts`**:

```typescript
import { defineConfig } from "tsup";

export default defineConfig({
  entry: { authkit: "src/authkit.ts" },
  format: ["iife"],
  splitting: false,
  sourcemap: true,
  dts: false,
  minify: false,
  clean: true,
  outDir: "dist",
});
```

**`tsconfig.json`**:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "preserve",
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "outDir": "dist",
    "declaration": false
  },
  "include": ["src"],
  "exclude": ["src/__tests__"]
}
```

## Testing Requirements

### Unit Tests

| Test File                       | Coverage                                                                    |
| ------------------------------- | --------------------------------------------------------------------------- |
| `src/__tests__/pkce.test.ts`    | PKCE verifier generation, S256 challenge, sessionStorage round-trip, expiry |
| `src/__tests__/urls.test.ts`    | Authorization URL params, logout URL, edge cases                            |
| `src/__tests__/token.test.ts`   | JWT base64url decoding, user extraction from response                       |
| `src/__tests__/session.test.ts` | localStorage store/get/clear, malformed data handling                       |
| `src/__tests__/authkit.test.ts` | Config parsing, auto-callback detection, event dispatch, missing client ID  |

**Key test cases**:

- `randomString()` produces correct length with valid characters
- `createPkceBundle()` returns distinct verifier and challenge
- S256 challenge matches known test vector (RFC 7636 Appendix B)
- `createAuthorizeUrl()` includes all required params (`client_id`, `redirect_uri`, `response_type`, `code_challenge`, `code_challenge_method`, `state`)
- `createAuthorizeUrl()` omits optional params when not provided
- `decodeJwtClaims()` correctly decodes base64url payload
- `decodeJwtClaims()` returns null for malformed tokens
- `storeSession()` + `getSession()` round-trips correctly
- `getSession()` returns null for missing/corrupt data
- Missing `data-client-id` logs error, does not assign `window.AuthKit`
- Callback URL detection matches redirect URI pathname
- `authkit:ready` event fires after initialization

### Manual Testing

- [ ] Create minimal `index.html` with script tag, verify `window.AuthKit` in console
- [ ] `AuthKit.signIn()` redirects to WorkOS hosted auth page
- [ ] Complete sign-in flow, verify auto-callback processes and `AuthKit.getUser()` returns user
- [ ] Reload page, verify session persists from localStorage
- [ ] `AuthKit.signOut()` clears session and redirects
- [ ] `document.addEventListener("authkit:ready", ...)` fires with user detail

## Error Handling

| Error Scenario                    | Handling Strategy                                                                        |
| --------------------------------- | ---------------------------------------------------------------------------------------- |
| Missing `data-client-id`          | `console.error` with clear message, skip initialization, do not assign `window.AuthKit`  |
| PKCE verifier missing on callback | `console.error`, clean URL, resolve ready with `null` user                               |
| State mismatch on callback        | `console.error`, clear PKCE, resolve ready with `null` user                              |
| PKCE expired (>10 min)            | `console.error`, clear PKCE, resolve ready with `null` user                              |
| Token exchange HTTP error         | `console.error` with status, clear PKCE, resolve ready with `null` user                  |
| Malformed JWT in access token     | `decodeJwtClaims` returns `null`, `signOut` falls back to reload                         |
| `localStorage` unavailable        | `getSession` returns `null`, session won't persist across reloads (graceful degradation) |
| `crypto.subtle` unavailable       | PKCE generation fails, `console.error`, sign-in won't work (hard requirement)            |

## Validation Commands

```bash
# Install dependencies
npm install

# Type checking
npx tsc --noEmit

# Unit tests
npm test

# Format check
npm run format:check

# Build
npm run build

# Verify output
ls -la dist/authkit.js
wc -c dist/authkit.js
```

## Open Items

- [ ] Confirm WorkOS `/user_management/authenticate` accepts `code_verifier` without `client_secret` for public clients (authkit-js does this today, but verify endpoint behavior)
- [ ] Decide output filename: `authkit.js` vs `authkit.iife.js`
- [ ] Consider adding a `data-redirect-path` convenience attribute (sets redirectUri to `origin + path`) as an alternative to full `data-redirect-uri`

---

_This spec is ready for implementation. Follow the patterns and validate at each step._
