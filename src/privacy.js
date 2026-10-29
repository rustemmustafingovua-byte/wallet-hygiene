/**
 * Outbound privacy gate.
 *
 * Wallet private keys, seed phrases, and discovered access tokens are registered
 * in-process and refused on every outbound request. Signed transactions and
 * x402 payment payloads are allowed through only when they do not contain those
 * values and do not carry secret field names.
 */

const heldHex = new Set()
const heldExact = new Set()

const BARE_KEY = /0x[a-fA-F0-9]{64}(?![a-fA-F0-9])/
const BEARER = /\b(?:ghp|gho|github_pat|npm)_[A-Za-z0-9_]{20,}\b/
const SEED = /\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b/i
const SEED_CONTEXT = /seed|mnemonic|recovery phrase|keystore/i
const FORBIDDEN_FIELD = /"(?:privateKey|private_key|mnemonic|seedPhrase|seed_phrase|secretKey)"\s*:/i

export class SecretEgressError extends Error {
  constructor() {
    super("refusing to transmit private keys or secrets")
    this.name = "SecretEgressError"
  }
}

export function resetSecretRegistry() {
  heldHex.clear()
  heldExact.clear()
}

/** Remember a secret so a later network call cannot include it. */
export function registerSecret(value) {
  if (value == null) return
  const s = String(value).trim()
  if (s.length < 16) return
  if (/^(0x)?[a-fA-F0-9]{64}$/.test(s)) {
    heldHex.add(s.toLowerCase().replace(/^0x/, ""))
    return
  }
  heldExact.add(s)
}

export function textHasHeldSecret(text) {
  const s = String(text ?? "")
  const lower = s.toLowerCase()
  for (const hex of heldHex) {
    if (lower.includes(hex)) return true
  }
  for (const secret of heldExact) {
    if (s.includes(secret)) return true
  }
  return false
}

/** User-supplied API or CLI text. Reject keys even if this process has not seen them before. */
export function userInputHasSecret(value) {
  const s = typeof value === "string" ? value : JSON.stringify(value ?? "")
  if (textHasHeldSecret(s)) return true
  if (BARE_KEY.test(s)) return true
  if (BEARER.test(s)) return true
  if (FORBIDDEN_FIELD.test(s)) return true
  if (SEED_CONTEXT.test(s) && SEED.test(s)) return true
  return false
}

/**
 * Outbound body/URL/header check.
 * A 32-byte hex nonce inside an x402 payload is not itself a private key, so
 * bare 64-hex values are blocked only when they match a secret this process holds.
 */
export function outboundHasSecret(value) {
  const s = typeof value === "string" ? value : JSON.stringify(value ?? "")
  if (textHasHeldSecret(s)) return true
  if (BEARER.test(s)) return true
  if (FORBIDDEN_FIELD.test(s)) return true
  if (SEED_CONTEXT.test(s) && SEED.test(s)) return true
  return false
}

export function assertSafeOutbound(value) {
  if (outboundHasSecret(value)) throw new SecretEgressError()
}

export function redact(text) {
  let s = String(text ?? "")
  for (const hex of heldHex) {
    s = s.replace(new RegExp(hex, "ig"), "[redacted]")
  }
  for (const secret of heldExact) {
    s = s.split(secret).join("[redacted]")
  }
  return s
}

function asText(body) {
  if (body == null) return ""
  if (typeof body === "string") return body
  if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) return body.toString()
  if (typeof Buffer !== "undefined" && Buffer.isBuffer(body)) return body.toString("utf8")
  return ""
}

function headersText(headers) {
  if (!headers) return ""
  if (typeof headers.forEach === "function") {
    const parts = []
    headers.forEach((value, key) => parts.push(`${key}: ${value}`))
    return parts.join("\n")
  }
  return JSON.stringify(headers)
}

/** fetch wrapper. Every RPC and facilitator call goes through this. */
export function createGuardedFetch(fetchImpl = globalThis.fetch) {
  return async function guardedFetch(input, init = {}) {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input?.url
    assertSafeOutbound(url ?? "")
    assertSafeOutbound(asText(init.body))
    assertSafeOutbound(headersText(init.headers))
    return fetchImpl(input, init)
  }
}

/**
 * If wallet keys were placed in the environment, remember them so they cannot
 * be forwarded. Facilitator auth is intentionally sent to the facilitator and
 * is not registered; a value that looks like a wallet key is refused.
 */
export function sealEnvironmentSecrets(env = process.env) {
  if (env.WALLET_HYGIENE_KEYS) {
    try {
      const parsed = JSON.parse(env.WALLET_HYGIENE_KEYS)
      if (parsed && typeof parsed === "object") {
        for (const value of Object.values(parsed)) registerSecret(value)
      }
    } catch {
      // malformed JSON is handled when a sweep actually loads the map
    }
  }
  const auth = env.X402_FACILITATOR_AUTH
  if (auth && BARE_KEY.test(auth)) {
    throw new Error("X402_FACILITATOR_AUTH looks like a wallet private key")
  }
}
