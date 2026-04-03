export { PalAuthServer, PalAuthError } from "./server.js";
export type {
  PalAuthServerConfig,
  TokenInfo,
  UserDetail,
  UserListResult,
  UserListOptions,
  PalAuthErrorBody,
} from "./types.js";

import type { PalAuthServerConfig } from "./types.js";
import { PalAuthServer } from "./server.js";

/** Create a PalAuth server SDK instance. */
export function createAuthServer(config: PalAuthServerConfig): PalAuthServer {
  return new PalAuthServer(config);
}
