import { createServer } from "node:http"
import { readFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"
import { isAddress } from "./address.js"
import { balancesAt } from "./balances.js"
import { CHAINS } from "./chains.js"
import { SecretEgressError, sealEnvironmentSecrets, userInputHasSecret } from "./privacy.js"
import {
  assertPaymentReady,
  buildPaymentRequired,
  decodeHeader,
  encodeHeader,
  payloadMatches,
  paymentConfig,
  sanitizePaymentPayload,
  settlePayment,
  verifyPayment,
} from "./x402.js"

const here = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8"))

const buckets = new Map()

export function resetQuota() {
  buckets.clear()
}

export function takeFreeCredit(id, quota, now = Date.now()) {
  if (quota <= 0) return false
  const windowMs = 24 * 60 * 60 * 1000
  let bucket = buckets.get(id)
  if (!bucket || now - bucket.start >= windowMs) {
    bucket = { start: now, used: 0 }
    buckets.set(id, bucket)
  }
  if (buckets.size > 10_000) buckets.clear()
  if (bucket.used >= quota) return false
  bucket.used += 1
  return true
}

function sendJson(res, status, body, headers = {}) {
  const payload = JSON.stringify(body)
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    ...headers,
  })
  res.end(payload)
}

function clientId(req) {
  const fwd = req.headers["x-forwarded-for"]
  if (typeof fwd === "string" && fwd.length > 0 && fwd.length < 200 && !fwd.includes("\n")) {
    return fwd.split(",")[0].trim()
  }
  return req.socket?.remoteAddress || "local"
}

function resourceUrl(req) {
  const host = req.headers.host
  const safeHost = typeof host === "string" && /^[A-Za-z0-9.:_-]+$/.test(host) ? host : "localhost"
  const proto = req.headers["x-forwarded-proto"] === "https" ? "https" : "http"
  const path = (req.url || "/").split("?")[0]
  return `${proto}://${safeHost}${path}`
}

function readBody(req, limit = 32_768) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on("data", (chunk) => {
      size += chunk.length
      if (size > limit) {
        reject(Object.assign(new Error("body too large"), { status: 413 }))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")))
    req.on("error", reject)
  })
}

async function defaultLookup({ addresses, chains, fetchFn }) {
  const reports = []
  for (const address of addresses) {
    for (const chainKey of chains) {
      const balances = await balancesAt(chainKey, address, [], { fetchFn })
      reports.push({
        address,
        chain: chainKey,
        balances: balances.map((b) => ({
          symbol: b.symbol,
          decimals: b.decimals,
          amount: b.amount.toString(),
        })),
      })
    }
  }
  return reports
}

function parseRequestTarget(url) {
  const q = url.indexOf("?")
  const path = q === -1 ? url : url.slice(0, q)
  const params = new URLSearchParams(q === -1 ? "" : url.slice(q + 1))
  return { path, params }
}

/**
 * Paid surface is public balance lookups only. Private keys are rejected
 * before any RPC or facilitator call. Scanning files is not offered here.
 */
export function createApiServer({ env = process.env, fetchFn = globalThis.fetch, lookup = defaultLookup } = {}) {
  sealEnvironmentSecrets(env)
  const config = paymentConfig(env)
  assertPaymentReady(config)

  return createServer((req, res) => {
    handle(req, res, { env, fetchFn, lookup, config }).catch((err) => {
      if (res.headersSent) return
      const status = err instanceof SecretEgressError ? 400 : err.status || 500
      const error = status === 400 ? "rejected" : status === 413 ? "body_too_large" : "internal"
      sendJson(res, status, { error })
    })
  })
}

async function handle(req, res, ctx) {
  const method = req.method || "GET"
  if (method === "OPTIONS") {
    res.writeHead(204, {
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type, PAYMENT-SIGNATURE",
      "access-control-allow-methods": "GET, POST, OPTIONS",
    })
    res.end()
    return
  }
  res.setHeader("access-control-allow-origin", "*")
  const { path, params } = parseRequestTarget(req.url || "/")

  if (method === "GET" && path === "/health") {
    sendJson(res, 200, {
      ok: true,
      service: "wallet-hygiene",
      version: pkg.version,
      payments: ctx.config.enabled ? "enabled" : "disabled",
    })
    return
  }

  if (method === "GET" && path === "/v1/pricing") {
    sendJson(res, 200, publicPricing(ctx.config))
    return
  }

  if ((method === "GET" || method === "POST") && path === "/v1/balances") {
    await balancesRoute(req, res, ctx, method, params)
    return
  }

  sendJson(res, 404, { error: "not_found" })
}

function publicPricing(config) {
  return {
    service: "wallet-hygiene",
    version: pkg.version,
    payments: config.enabled ? "enabled" : "disabled",
    note: config.enabled
      ? "Free quota, then HTTP 402 with a PAYMENT-REQUIRED header (x402 v2)."
      : "Payments are off. Set X402_ENABLED=true and X402_PAY_TO to charge.",
    freeQuota: config.enabled ? config.freeQuota : null,
    accepts: config.enabled
      ? [{
          scheme: "exact",
          network: config.network,
          amount: config.amount,
          asset: config.asset,
          payTo: config.payTo,
          maxTimeoutSeconds: config.timeoutSeconds,
        }]
      : [],
  }
}

async function balancesRoute(req, res, ctx, method, params) {
  const rawQuery = params.toString()
  if (userInputHasSecret(rawQuery)) {
    sendJson(res, 400, { error: "secrets_not_accepted" })
    return
  }

  let addresses = []
  let chains = (params.get("chains") || "base").split(",").map((s) => s.trim()).filter(Boolean)
  if (method === "GET") {
    const one = params.get("address")
    if (one) addresses = [one]
  } else {
    const text = await readBody(req)
    if (userInputHasSecret(text)) {
      sendJson(res, 400, { error: "secrets_not_accepted" })
      return
    }
    let body
    try {
      body = text ? JSON.parse(text) : {}
    } catch {
      sendJson(res, 400, { error: "invalid_json" })
      return
    }
    if (Array.isArray(body.addresses)) addresses = body.addresses
    else if (typeof body.address === "string") addresses = [body.address]
    if (Array.isArray(body.chains) && body.chains.length) chains = body.chains.map(String)
  }

  if (!addresses.length || addresses.length > ctx.config.maxAddresses) {
    sendJson(res, 400, { error: "invalid_addresses", max: ctx.config.maxAddresses })
    return
  }
  if (!addresses.every(isAddress)) {
    sendJson(res, 400, { error: "invalid_addresses" })
    return
  }
  if (!chains.length || chains.some((c) => !CHAINS[c])) {
    sendJson(res, 400, { error: "invalid_chains", known: Object.keys(CHAINS) })
    return
  }

  const paid = await authorize(req, res, ctx)
  if (!paid.ok) return

  let reports
  try {
    reports = await ctx.lookup({
      addresses: addresses.map((a) => a.toLowerCase()),
      chains,
      fetchFn: ctx.fetchFn,
    })
  } catch (err) {
    if (err instanceof SecretEgressError) throw err
    sendJson(res, 502, { error: "rpc_failed" })
    return
  }

  if (paid.settle) {
    const settled = await paid.settle()
    if (!settled.ok) {
      sendJson(res, 402, { error: settled.error || "settlement_failed" })
      return
    }
    sendJson(res, 200, { payments: "paid", reports }, {
      "PAYMENT-RESPONSE": encodeHeader(settled.response),
    })
    return
  }

  sendJson(res, 200, {
    payments: ctx.config.enabled ? "free" : "disabled",
    reports,
  })
}

async function authorize(req, res, ctx) {
  if (!ctx.config.enabled) return { ok: true, settle: null }
  if (takeFreeCredit(clientId(req), ctx.config.freeQuota)) return { ok: true, settle: null }

  const header = req.headers["payment-signature"]
  const payload = decodeHeader(Array.isArray(header) ? header[0] : header)
  const url = resourceUrl(req)
  const requirePayment = (error) => {
    const required = buildPaymentRequired({ config: ctx.config, resourceUrl: url, error })
    sendJson(res, 402, required, { "PAYMENT-REQUIRED": encodeHeader(required) })
    return { ok: false }
  }
  if (!payload) return requirePayment("PAYMENT-SIGNATURE header is required")
  const clean = sanitizePaymentPayload(payload, ctx.config)
  if (!clean || !payloadMatches(payload, ctx.config)) return requirePayment("invalid payment payload")
  const verified = await verifyPayment({
    config: ctx.config,
    payload: clean,
    fetchFn: ctx.fetchFn,
  })
  if (!verified.ok) return requirePayment(verified.error)
  return {
    ok: true,
    settle: () => settlePayment({ config: ctx.config, payload: clean, fetchFn: ctx.fetchFn }),
  }
}

export function listen(server, { host, port } = {}, env = process.env) {
  const bindHost = host || env.HOST || env.WALLET_HYGIENE_HOST || "127.0.0.1"
  const bindPort = Number(port ?? env.PORT ?? 8787)
  return new Promise((resolve, reject) => {
    server.once("error", reject)
    server.listen(bindPort, bindHost, () => {
      const addr = server.address()
      resolve({ host: bindHost, port: typeof addr === "object" ? addr.port : bindPort })
    })
  })
}
