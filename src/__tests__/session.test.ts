import { describe, it, expect, beforeEach } from "vitest";
import { storeSession, getSession, clearSession } from "../session";
import type { AuthKitUser } from "../types";

beforeEach(() => {
  localStorage.clear();
});

const testUser: AuthKitUser = {
  sub: "user_123",
  email: "test@example.com",
  firstName: "Test",
  lastName: "User",
};

describe("storeSession / getSession", () => {
  it("round-trips session data", () => {
    storeSession("access_token_abc", testUser);
    const session = getSession();

    expect(session).not.toBeNull();
    expect(session!.accessToken).toBe("access_token_abc");
    expect(session!.user).toEqual(testUser);
    expect(session!.storedAt).toBeGreaterThan(0);
  });

  it("returns null when no session stored", () => {
    expect(getSession()).toBeNull();
  });

  it("returns null for malformed JSON in localStorage", () => {
    localStorage.setItem("authkit:session", "not valid json{{{");
    expect(getSession()).toBeNull();
  });
});

describe("clearSession", () => {
  it("removes session from localStorage", () => {
    storeSession("token", testUser);
    expect(getSession()).not.toBeNull();

    clearSession();
    expect(getSession()).toBeNull();
  });
});
