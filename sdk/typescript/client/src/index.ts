export { PalAuthClient, PalAuthError } from "./client.js";
export type {
  PalAuthClientConfig,
  AuthResult,
  TokenResponse,
  IntrospectionResponse,
  Session,
  UserInfo,
  PalAuthErrorBody,
  SignupParams,
  SignInParams,
  VerifyEmailParams,
  PasswordResetParams,
  PasswordResetConfirmParams,
  PasswordChangeParams,
} from "./types.js";

import type { PalAuthClientConfig } from "./types.js";
import { PalAuthClient } from "./client.js";

/** Create a PalAuth client instance. */
export function createAuthClient(config: PalAuthClientConfig): PalAuthClient {
  return new PalAuthClient(config);
}
