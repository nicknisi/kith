import { describe, it, expect } from "vitest";
import { decodeJwtClaims, extractUser } from "../token";
import type { TokenResponse } from "../types";

describe("decodeJwtClaims", () => {
  it("decodes a valid JWT payload", () => {
    const payload = btoa(
      JSON.stringify({
        sub: "user_123",
        email: "test@example.com",
        sid: "sess_abc",
      }),
    );
    const token = `eyJhbGciOiJSUzI1NiJ9.${payload}.fake_signature`;

    const claims = decodeJwtClaims(token);
    expect(claims).toEqual({
      sub: "user_123",
      email: "test@example.com",
      sid: "sess_abc",
    });
  });

  it("handles base64url encoding (- and _ chars)", () => {
    const payloadObj = { sub: "user_123", data: "a+b/c==" };
    const standardB64 = btoa(JSON.stringify(payloadObj));
    const urlSafe = standardB64
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    const token = `header.${urlSafe}.sig`;
    const claims = decodeJwtClaims(token);
    expect(claims).toEqual(payloadObj);
  });

  it("returns null for malformed token (not 3 parts)", () => {
    expect(decodeJwtClaims("not.a.valid.jwt.token")).toBeNull();
    expect(decodeJwtClaims("onlyone")).toBeNull();
    expect(decodeJwtClaims("two.parts")).toBeNull();
  });

  it("returns null for invalid base64", () => {
    expect(decodeJwtClaims("h.!!!invalid!!!.s")).toBeNull();
  });

  it("returns null for non-JSON payload", () => {
    const notJson = btoa("this is not json");
    expect(decodeJwtClaims(`h.${notJson}.s`)).toBeNull();
  });
});

describe("extractUser", () => {
  it("maps WorkOS user response to AuthKitUser", () => {
    const response: TokenResponse = {
      access_token: "at_123",
      user: {
        id: "user_abc",
        email: "test@example.com",
        first_name: "Jane",
        last_name: "Doe",
        email_verified: true,
        profile_picture_url: "https://example.com/avatar.jpg",
        created_at: "2024-01-01T00:00:00Z",
        updated_at: "2024-01-01T00:00:00Z",
      },
    };

    const user = extractUser(response);
    expect(user).toEqual({
      sub: "user_abc",
      email: "test@example.com",
      firstName: "Jane",
      lastName: "Doe",
      profilePictureUrl: "https://example.com/avatar.jpg",
    });
  });

  it("handles null fields as undefined", () => {
    const response: TokenResponse = {
      access_token: "at_123",
      user: {
        id: "user_abc",
        email: "test@example.com",
        first_name: null,
        last_name: null,
        email_verified: false,
        profile_picture_url: null,
        created_at: "2024-01-01T00:00:00Z",
        updated_at: "2024-01-01T00:00:00Z",
      },
    };

    const user = extractUser(response);
    expect(user.firstName).toBeUndefined();
    expect(user.lastName).toBeUndefined();
    expect(user.profilePictureUrl).toBeUndefined();
  });
});
