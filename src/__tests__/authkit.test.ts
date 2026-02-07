import { describe, it, expect, beforeEach, vi } from "vitest";

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  delete (window as any).AuthKit;
  vi.resetModules();
});

function setCurrentScript(dataset: Record<string, string>) {
  const script = document.createElement("script");
  for (const [key, value] of Object.entries(dataset)) {
    script.dataset[key] = value;
  }
  Object.defineProperty(document, "currentScript", {
    value: script,
    writable: true,
    configurable: true,
  });
}

describe("config parsing", () => {
  it("logs error and does not assign window.AuthKit when client-id is missing", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    Object.defineProperty(document, "currentScript", {
      value: document.createElement("script"),
      writable: true,
      configurable: true,
    });

    await import("../authkit");

    expect(errorSpy).toHaveBeenCalledWith(
      expect.stringContaining("Missing required data-client-id"),
    );
    expect((window as any).AuthKit).toBeUndefined();
    errorSpy.mockRestore();
  });

  it("assigns window.AuthKit when client-id is provided", async () => {
    setCurrentScript({ clientId: "client_test" });
    await import("../authkit");

    expect((window as any).AuthKit).toBeDefined();
    expect(typeof (window as any).AuthKit.signIn).toBe("function");
    expect(typeof (window as any).AuthKit.signUp).toBe("function");
    expect(typeof (window as any).AuthKit.signOut).toBe("function");
    expect(typeof (window as any).AuthKit.getUser).toBe("function");
    expect(typeof (window as any).AuthKit.getAccessToken).toBe("function");
    expect((window as any).AuthKit.ready).toBeInstanceOf(Promise);
  });
});

describe("ready event and promise", () => {
  it("dispatches authkit:ready event", async () => {
    setCurrentScript({ clientId: "client_test" });

    const eventPromise = new Promise<CustomEvent>((resolve) => {
      document.addEventListener(
        "authkit:ready",
        (e) => resolve(e as CustomEvent),
        {
          once: true,
        },
      );
    });

    await import("../authkit");

    const event = await eventPromise;
    expect(event.detail).toEqual({ user: null });
  });

  it("resolves ready promise with null user when no session", async () => {
    setCurrentScript({ clientId: "client_test" });
    await import("../authkit");

    const result = await (window as any).AuthKit.ready;
    expect(result).toEqual({ user: null });
  });

  it("resolves ready promise with existing user from localStorage", async () => {
    const session = {
      accessToken: "token_abc",
      user: { sub: "user_123", email: "test@example.com" },
      storedAt: Date.now(),
    };
    localStorage.setItem("authkit:session", JSON.stringify(session));

    setCurrentScript({ clientId: "client_test" });
    await import("../authkit");

    const result = await (window as any).AuthKit.ready;
    expect(result.user).toEqual(session.user);
  });
});

describe("getUser / getAccessToken", () => {
  it("returns null when no session exists", async () => {
    setCurrentScript({ clientId: "client_test" });
    await import("../authkit");

    expect((window as any).AuthKit.getUser()).toBeNull();
    expect((window as any).AuthKit.getAccessToken()).toBeNull();
  });

  it("returns user and token from existing session", async () => {
    const session = {
      accessToken: "token_abc",
      user: { sub: "user_123", email: "test@example.com" },
      storedAt: Date.now(),
    };
    localStorage.setItem("authkit:session", JSON.stringify(session));

    setCurrentScript({ clientId: "client_test" });
    await import("../authkit");

    expect((window as any).AuthKit.getUser()).toEqual(session.user);
    expect((window as any).AuthKit.getAccessToken()).toBe("token_abc");
  });
});
