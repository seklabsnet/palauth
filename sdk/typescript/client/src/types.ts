/** Configuration for PalAuth client. */
export interface PalAuthClientConfig {
  /** Base URL of the PalAuth server (e.g. "https://auth.example.com"). */
  url: string;
  /** Public API key (pk_test_* or pk_live_*). */
  apiKey: string;
  /** Custom fetch implementation (defaults to globalThis.fetch). */
  fetch?: typeof globalThis.fetch;
}

/** User information returned from auth operations. */
export interface UserInfo {
  id: string;
  email: string;
  email_verified: boolean;
  created_at: string;
}

/** Result of a signup or login operation. */
export interface AuthResult {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: UserInfo;
  verification_token?: string;
  verification_code?: string;
}

/** Token response from refresh or exchange operations. */
export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

/** Token introspection response. */
export interface IntrospectionResponse {
  active: boolean;
  sub?: string;
  scope?: string;
  exp?: number;
  iat?: number;
  project_id?: string;
  token_type?: string;
  jti?: string;
}

/** Session information. */
export interface Session {
  id: string;
  ip?: string;
  user_agent?: string;
  acr: string;
  amr: string[];
  last_activity: string;
  created_at: string;
  current: boolean;
}

/** PalAuth API error. */
export interface PalAuthErrorBody {
  error: string;
  error_description: string;
  status: number;
  request_id: string;
}

/** Signup parameters. */
export interface SignupParams {
  email: string;
  password: string;
}

/** Sign-in parameters. */
export interface SignInParams {
  email: string;
  password: string;
}

/** Verify email parameters. */
export interface VerifyEmailParams {
  token?: string;
  code?: string;
  email?: string;
}

/** Password reset request parameters. */
export interface PasswordResetParams {
  email: string;
}

/** Password reset confirm parameters. */
export interface PasswordResetConfirmParams {
  token: string;
  new_password: string;
}

/** Password change parameters. */
export interface PasswordChangeParams {
  current_password: string;
  new_password: string;
}
