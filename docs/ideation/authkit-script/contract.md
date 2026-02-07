# AuthKit Script Tag Contract

**Created**: 2026-02-06
**Confidence Score**: 96/100
**Status**: Approved

## Problem Statement

Developers building static sites, WordPress pages, or no-build prototypes can't use WorkOS AuthKit without npm and a bundler. The existing authkit-js SDK is designed for SPAs with build pipelines. shoo.js proves that a single `<script>` tag with `data-*` configuration can provide a complete OAuth PKCE flow in the browser. WorkOS needs an equivalent: a standalone, zero-dependency script that authenticates users against the WorkOS API with nothing more than a script tag and a client ID.

## Goals

1. **Ship a standalone IIFE script** (`authkit.js`) that provides complete OAuth 2.0 PKCE authentication against WorkOS `/user_management/authorize` and `/user_management/authenticate` endpoints
2. **Configure entirely via `data-*` attributes** on the script tag — `data-client-id` (required), `data-redirect-uri`, `data-api-hostname`
3. **Auto-bootstrap** — detect and process OAuth callbacks automatically, expose `window.AuthKit` with ready promise and client methods
4. **Dispatch custom DOM events** (`authkit:ready`, `authkit:signed-in`, `authkit:signed-out`) for vanilla JS integration
5. **Zero runtime dependencies** — self-contained PKCE, JWT decoding, token storage, all in one file

## Success Criteria

- [ ] `<script src="authkit.js" data-client-id="client_xxx"></script>` is the only integration needed
- [ ] Complete PKCE flow: generate verifier/challenge, redirect to `/user_management/authorize`, exchange code at `/user_management/authenticate`
- [ ] `AuthKit.ready` promise resolves with `{ user }` after initialization
- [ ] `AuthKit.signIn()` and `AuthKit.signUp()` redirect to WorkOS hosted auth
- [ ] `AuthKit.getUser()` returns decoded user from stored access token
- [ ] `AuthKit.signOut()` clears local session and redirects to WorkOS logout
- [ ] `AuthKit.getAccessToken()` returns current JWT access token
- [ ] OAuth callback auto-handled when URL matches redirect path
- [ ] Custom events fire on `document` at appropriate lifecycle points
- [ ] Works in all browsers supporting `crypto.subtle` (modern browsers)
- [ ] Bundle under 10KB minified (it's just PKCE + fetch + storage glue)

## Scope Boundaries

### In Scope

- Complete PKCE implementation (code verifier, S256 challenge, code exchange)
- Authorization URL construction matching WorkOS `/user_management/authorize` params
- Token exchange via `POST /user_management/authenticate`
- JWT decoding (no signature verification — same as authkit-js and shoo.js)
- Access token + user storage in memory/localStorage
- `data-*` attribute configuration parsing
- Auto-callback detection and processing
- `window.AuthKit` global with `signIn`, `signUp`, `signOut`, `getUser`, `getAccessToken`, `ready`
- Custom DOM events
- Dev mode detection (localhost)
- Project scaffolding (package.json, tsup, TypeScript)

### Out of Scope

- Refresh token rotation — requires server-side cookie support, out of scope for v1 script tag
- Cross-tab session locking — complexity not justified for v1
- Organization switching — advanced feature, not needed for script tag use case
- npm package distribution — this is CDN-only
- TypeScript type definitions for consumers — script tag users don't use TS
- Automated tests for the PKCE crypto (well-established pattern, tested via integration)
- CI/CD pipeline — separate concern

### Future Considerations

- Refresh token support via `devMode` localStorage pattern
- Declarative `<a href="/authorize">` link interception (like shoo.js)
- `data-auto-sign-in` attribute to auto-redirect unauthenticated users
- Minified production build (`authkit.min.js`)
- Versioned CDN hosting
- Web component (`<authkit-login>`) for declarative UI

---

_This contract was generated from brain dump input. Review and approve before proceeding to specification._
