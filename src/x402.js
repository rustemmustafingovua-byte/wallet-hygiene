/**
 * x402 v2 HTTP transport (https://www.x402.org).
 * The facilitator verifies and settles. This process never signs a payment
 * and never sees the payer's private key.
 */

import { isAddress } from "./address.js"
import { assertSafeOutbound, createGuardedFetch, outboundHasSecret, userInputHasSecret } from "./privacy.js"

export const X402_VERSION = 2
export const BASE_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

function intEnv(value, fallback) {
  if (value == null || value === "") return fallback
  const n = Number(value)
  if (!Number.isInteger(n) || n < 0) return fallback
  return n
}

export function paymentConfig(env = process.env) {
  const enabled = env.X402_ENABLED === "true" || env.X402_ENABLED === "1"
  return {
    enabled,
    payTo: (env.X402_PAY_TO || "").trim(),
    network: env.X402_NETWORK || "eip155:8453",
    amount: env.X402_PRICE_ATOMIC || "10000",
    asset: env.X402_ASSET || BASE_USDC,
    facilitatorUrl: (env.X402_FACILITATOR_URL || "https://x402.org/facilitator").replace(/\/$/, ""),
    facilitatorAuth: env.X402_FACILITATOR_AUTH || "",
    freeQuota: intEnv(env.X402_FREE_QUOTA, 10),
    timeoutSeconds: intEnv(env.X402_TIMEOUT_SECONDS, 60),
    maxAddresses: Math.min(intEnv(env.X402_MAX_ADDRESSES, 20), 100),
  }
}

export function assertPaymentReady(config) {
  if (!config.enabled) return
  if (!isAddress(config.payTo)) throw new Error("X402_ENABLED requires X402_PAY_TO to be an 0x address")
  if (!isAddress(config.asset)) throw new Error("X402_ASSET must be an 0x token address")
  if (!/^eip155:\d+$/.test(config.network)) throw new Error("X402_NETWORK must look like eip155:8453")
  if (!/^[0-9]+$/.test(config.amount) || config.amount === "0") {
    throw new Error("X402_PRICE_ATOMIC must be a positive integer string")
  }
  if (!/^https?:\/\//.test(config.facilitatorUrl)) {
    throw new Error("X402_FACILITATOR_URL must be an http(s) URL")
  }
}

export function paymentRequirements(config) {
  return {
    scheme: "exact",
    network: config.network,
    amount: config.amount,
    asset: config.asset,
    payTo: config.payTo,
    maxTimeoutSeconds: config.timeoutSeconds,
    extra: { name: "USDC", version: "2" },
  }
}

export function buildPaymentRequired({ config, resourceUrl, error }) {
  return {
    x402Version: X402_VERSION,
    error: error || "PAYMENT-SIGNATURE header is required",
    resource: {
      url: resourceUrl,
      description: "Multi-chain public balance report for addresses you already have",
      mimeType: "application/json",
      serviceName: "wallet-hygiene",
    },
    accepts: [paymentRequirements(config)],
    extensions: {},
  }
}

export function encodeHeader(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64")
}

export function decodeHeader(value) {
  if (!value || typeof value !== "string") return null
  try {
    return JSON.parse(Buffer.from(value, "base64").toString("utf8"))
  } catch {
    return null
  }
}

function sameAddress(a, b) {
  return typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase()
}

/**
 * Keep only the exact-scheme fields the facilitator needs. Extra fields are
 * dropped so a client cannot hide a private key in the object we forward.
 */
export function sanitizePaymentPayload(payload, config) {
  const auth = payload?.payload?.authorization
  const signature = payload?.payload?.signature
  if (!auth || typeof auth !== "object") return null
  if (typeof signature !== "string" || !/^0x[a-fA-F0-9]{130}$/.test(signature)) return null
  if (!isAddress(auth.from) || !isAddress(auth.to)) return null
  if (typeof auth.value !== "string" || !/^[0-9]+$/.test(auth.value)) return null
  if (typeof auth.validAfter !== "string" || !/^[0-9]+$/.test(auth.validAfter)) return null
  if (typeof auth.validBefore !== "string" || !/^[0-9]+$/.test(auth.validBefore)) return null
  if (typeof auth.nonce !== "string" || !/^0x[a-fA-F0-9]{64}$/.test(auth.nonce)) return null
  const resource = {}
  const src = payload.resource
  if (src && typeof src === "object") {
    if (typeof src.url === "string" && src.url.length <= 2048 && /^https?:\/\//.test(src.url)) resource.url = src.url
    if (typeof src.description === "string" && src.description.length <= 300) resource.description = src.description
    if (typeof src.mimeType === "string" && /^[\w.+/-]{1,100}$/.test(src.mimeType)) resource.mimeType = src.mimeType
  }
  if (userInputHasSecret(JSON.stringify(resource))) return null
  const clean = {
    x402Version: X402_VERSION,
    resource,
    accepted: paymentRequirements(config),
    payload: {
      signature,
      authorization: {
        from: auth.from,
        to: auth.to,
        value: auth.value,
        validAfter: auth.validAfter,
        validBefore: auth.validBefore,
        nonce: auth.nonce,
      },
    },
  }
  if (outboundHasSecret(JSON.stringify(clean))) return null
  return clean
}

export function payloadMatches(payload, config) {
  const accepted = payload?.accepted
  if (!payload || payload.x402Version !== X402_VERSION || !accepted) return false
  if (accepted.scheme !== "exact") return false
  if (accepted.network !== config.network) return false
  if (accepted.amount !== config.amount) return false
  if (!sameAddress(accepted.asset, config.asset)) return false
  if (!sameAddress(accepted.payTo, config.payTo)) return false
  return true
}

async function postFacilitator(config, path, body, fetchFn) {
  assertSafeOutbound(body)
  const headers = { "content-type": "application/json" }
  if (config.facilitatorAuth) headers.authorization = `Bearer ${config.facilitatorAuth}`
  assertSafeOutbound(JSON.stringify(headers))
  const res = await createGuardedFetch(fetchFn)(`${config.facilitatorUrl}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  })
  const text = await res.text()
  assertSafeOutbound(text)
  let json = null
  try {
    json = JSON.parse(text)
  } catch {
    json = null
  }
  return { ok: res.ok, status: res.status, json }
}

/**
 * Authorization flow from the x402 v2 spec: verify, then the caller runs the
 * resource, then settle. Settlement is the facilitator's job.
 */
export async function verifyPayment({ config, payload, fetchFn }) {
  const body = {
    x402Version: X402_VERSION,
    paymentPayload: payload,
    paymentRequirements: paymentRequirements(config),
  }
  const verified = await postFacilitator(config, "/verify", body, fetchFn)
  if (!verified.ok || !verified.json?.isValid) {
    return {
      ok: false,
      error: verified.json?.invalidReason || "payment_verification_failed",
    }
  }
  return { ok: true, payer: verified.json.payer ?? null, requirements: paymentRequirements(config) }
}

export async function settlePayment({ config, payload, fetchFn }) {
  const body = {
    x402Version: X402_VERSION,
    paymentPayload: payload,
    paymentRequirements: paymentRequirements(config),
  }
  const settled = await postFacilitator(config, "/settle", body, fetchFn)
  if (!settled.ok || !settled.json?.success) {
    return { ok: false, error: settled.json?.errorReason || "settlement_failed", response: settled.json }
  }
  return { ok: true, response: settled.json }
}
