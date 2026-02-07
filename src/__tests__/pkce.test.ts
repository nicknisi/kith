import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { createPkceBundle, storePkce, retrievePkce, clearPkce } from "../pkce";

beforeAll(() => {
  if (!globalThis.crypto?.subtle) {
    const { webcrypto } = require("crypto");
    Object.defineProperty(globalThis, "crypto", { value: webcrypto });
  }
});

beforeEach(() => {
  sessionStorage.clear();
});

describe("createPkceBundle", () => {
  it("returns a bundle with state, codeVerifier, and codeChallenge", async () => {
    const bundle = await createPkceBundle();
    expect(bundle.state).toBeDefined();
    expect(bundle.codeVerifier).toBeDefined();
    expect(bundle.codeChallenge).toBeDefined();
  });

  it("generates a 64-char code verifier", async () => {
    const bundle = await createPkceBundle();
    expect(bundle.codeVerifier).toHaveLength(64);
  });

  it("generates a 32-char state", async () => {
    const bundle = await createPkceBundle();
    expect(bundle.state).toHaveLength(32);
  });

  it("uses only RFC 7636 unreserved characters in verifier", async () => {
    const bundle = await createPkceBundle();
    expect(bundle.codeVerifier).toMatch(/^[A-Za-z0-9\-._~]+$/);
  });

  it("produces distinct verifier and challenge", async () => {
    const bundle = await createPkceBundle();
    expect(bundle.codeVerifier).not.toBe(bundle.codeChallenge);
  });

  it("generates unique bundles on each call", async () => {
    const a = await createPkceBundle();
    const b = await createPkceBundle();
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
    expect(a.state).not.toBe(b.state);
  });

  it("produces a base64url-encoded challenge (no +, /, or =)", async () => {
    const bundle = await createPkceBundle();
    expect(bundle.codeChallenge).not.toMatch(/[+/=]/);
  });
});

describe("storePkce / retrievePkce / clearPkce", () => {
  it("round-trips a PKCE bundle", async () => {
    const bundle = await createPkceBundle();
    storePkce(bundle);

    const retrieved = retrievePkce();
    expect(retrieved).not.toBeNull();
    expect(retrieved!.state).toBe(bundle.state);
    expect(retrieved!.codeVerifier).toBe(bundle.codeVerifier);
  });

  it("returns null when nothing stored", () => {
    expect(retrievePkce()).toBeNull();
  });

  it("returns null for malformed data", () => {
    sessionStorage.setItem("authkit:pkce", "not json");
    expect(retrievePkce()).toBeNull();
  });

  it("returns null for expired PKCE (>10 min)", async () => {
    const bundle = await createPkceBundle();
    storePkce(bundle);

    const raw = JSON.parse(sessionStorage.getItem("authkit:pkce")!);
    raw.createdAt = Date.now() - 11 * 60 * 1000;
    sessionStorage.setItem("authkit:pkce", JSON.stringify(raw));

    expect(retrievePkce()).toBeNull();
  });

  it("clears PKCE data", async () => {
    const bundle = await createPkceBundle();
    storePkce(bundle);
    clearPkce();
    expect(retrievePkce()).toBeNull();
  });
});
