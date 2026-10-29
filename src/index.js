/**
 * wallet-hygiene public API.
 *
 * Scans and sweeps stay on the machine that holds the keys. The HTTP API
 * accepts public addresses only. See docs/SECURITY.md.
 */
export { isAddress } from "./address.js"
export { createApiServer, listen } from "./api.js"
export { balancesAt, createChainClient } from "./balances.js"
export { CHAINS, chainRpc } from "./chains.js"
export { loadConfig, loadKeyMap, readAllowlist, saveConfig } from "./config.js"
export {
  SecretEgressError,
  createGuardedFetch,
  registerSecret,
  resetSecretRegistry,
  sealEnvironmentSecrets,
} from "./privacy.js"
export {
  KNOWN_DEV_KEYS,
  KNOWN_TOKEN_ADDRESSES,
  findKeyLeaks,
  findOwnAddresses,
  isKnownConstant,
  isTrackedByGit,
  walk,
} from "./scan.js"
export { planNativeSweep, sweepOne } from "./sweep.js"
export { paymentConfig, buildPaymentRequired } from "./x402.js"
