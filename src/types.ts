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
