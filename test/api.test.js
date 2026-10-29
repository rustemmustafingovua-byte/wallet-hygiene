import { test } from "node:test"
import assert from "node:assert/strict"
import { generatePrivateKey } from "viem/accounts"
import { createApiServer, listen, resetQuota } from "../src/api.js"
import { resetSecretRegistry } from "../src/privacy.js"
import { paymentConfig, decodeHeader, BASE_USDC } from "../src/x402.js"

const PAY_TO = `0x${"1".repeat(40)}`

function enabledEnv(extra = {}) {
  return {
    X402_ENABLED: "true",
    X402_PAY_TO: PAY_TO,
    X402_FREE_QUOTA: "0",
    X402_FACILITATOR_URL: "https://facilitator.test",
    ...extra,
  }
}

function paymentPayload() {
  const config = paymentConfig(enabledEnv())
  return {
    x402Version: 2,
    accepted: {
      scheme: "exact",
      network: config.network,
      amount: config.amount,
      asset: config.asset,
      payTo: config.payTo,
      maxTimeoutSeconds: config.timeoutSeconds,
      extra: { name: "USDC", version: "2" },
    },
    payload: {
      signature: `0x${"d".repeat(130)}`,
      authorization: {
        from: `0x${"9".repeat(40)}`,
        to: config.payTo,
        value: config.amount,
        validAfter: "0",
        validBefore: "9999999999",
        nonce: `0x${"c".repeat(64)}`,
      },
    },
  }
}

async function start(opts) {
  resetQuota()
  resetSecretRegistry()
  const server = createApiServer(opts)
  const addr = await listen(server, { host: "127.0.0.1", port: 0 })
  return {
    base: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  }
}

test("health и pricing не требуют оплаты, пока x402 выключен", async () => {
  const seen = []
  const api = await start({
    env: {},
    fetchFn: async (url) => {
      seen.push(String(url))
      throw new Error("network")
    },
    lookup: async () => [{ address: `0x${"a".repeat(40)}`, chain: "base", balances: [] }],
  })
  try {
    const health = await fetch(`${api.base}/health`)
    assert.equal(health.status, 200)
    const body = await health.json()
    assert.equal(body.payments, "disabled")
    const pricing = await fetch(`${api.base}/v1/pricing`)
    assert.equal((await pricing.json()).payments, "disabled")
    const report = await fetch(`${api.base}/v1/balances?address=${"0x" + "a".repeat(40)}&chains=base`)
    assert.equal(report.status, 200)
    assert.equal((await report.json()).payments, "disabled")
    assert.equal(seen.length, 0)
  } finally {
    await api.close()
  }
})

test("после бесплатной квоты сервер отвечает 402 в формате x402 v2", async () => {
  const api = await start({
    env: enabledEnv({ X402_FREE_QUOTA: "1" }),
    fetchFn: async () => {
      throw new Error("facilitator should not be called")
    },
    lookup: async () => [],
  })
  try {
    const address = `0x${"b".repeat(40)}`
    const first = await fetch(`${api.base}/v1/balances?address=${address}&chains=base`)
    assert.equal(first.status, 200)
    assert.equal((await first.json()).payments, "free")
    const second = await fetch(`${api.base}/v1/balances?address=${address}&chains=base`)
    assert.equal(second.status, 402)
    const header = second.headers.get("payment-required")
    const required = decodeHeader(header)
    assert.equal(required.x402Version, 2)
    assert.equal(required.accepts[0].scheme, "exact")
    assert.equal(required.accepts[0].network, "eip155:8453")
    assert.equal(required.accepts[0].amount, "10000")
    assert.equal(required.accepts[0].payTo.toLowerCase(), PAY_TO)
    assert.equal(required.accepts[0].asset.toLowerCase(), BASE_USDC.toLowerCase())
    const echoed = await second.json()
    assert.equal(echoed.x402Version, 2)
    assert.equal(echoed.accepts[0].payTo.toLowerCase(), PAY_TO)
  } finally {
    await api.close()
  }
})

test("оплаченный запрос проверяется и сеттлится через фасилитатор, ключ на провод не попадает", async () => {
  const privateKey = generatePrivateKey()
  const smuggled = generatePrivateKey()
  const calls = []
  const fetchFn = async (url, init) => {
    calls.push({ url: String(url), body: String(init?.body ?? ""), headers: init?.headers })
    if (String(url).endsWith("/verify")) {
      return new Response(JSON.stringify({ isValid: true, payer: `0x${"9".repeat(40)}` }), {
        headers: { "content-type": "application/json" },
      })
    }
    if (String(url).endsWith("/settle")) {
      return new Response(JSON.stringify({
        success: true,
        transaction: `0x${"ab".repeat(32)}`,
        network: "eip155:8453",
        payer: `0x${"9".repeat(40)}`,
      }), { headers: { "content-type": "application/json" } })
    }
    throw new Error(`unexpected ${url}`)
  }
  const api = await start({
    env: enabledEnv({
      WALLET_HYGIENE_KEYS: JSON.stringify({ [`0x${"e".repeat(40)}`]: privateKey }),
      X402_FACILITATOR_AUTH: "facilitator-token",
    }),
    fetchFn,
    lookup: async () => [{ address: `0x${"a".repeat(40)}`, chain: "base", balances: [{ symbol: "ETH", amount: "1" }] }],
  })
  try {
    const payload = paymentPayload()
    payload.privateKey = smuggled
    payload.payload.note = smuggled
    const res = await fetch(`${api.base}/v1/balances?address=${"0x" + "a".repeat(40)}&chains=base`, {
      headers: { "payment-signature": Buffer.from(JSON.stringify(payload)).toString("base64") },
    })
    assert.equal(res.status, 200)
    const settlement = decodeHeader(res.headers.get("payment-response"))
    assert.equal(settlement.success, true)
    assert.equal((await res.json()).payments, "paid")
    assert.deepEqual(calls.map((c) => c.url), [
      "https://facilitator.test/verify",
      "https://facilitator.test/settle",
    ])
    const wire = JSON.stringify(calls)
    assert.equal(wire.toLowerCase().includes(privateKey.slice(2).toLowerCase()), false)
    assert.equal(wire.toLowerCase().includes(smuggled.slice(2).toLowerCase()), false)
    assert.match(calls[0].headers.authorization, /^Bearer facilitator-token$/)
  } finally {
    await api.close()
  }
})

test("тело с приватным ключом отклоняется и не уходит в RPC", async () => {
  const key = generatePrivateKey()
  let called = 0
  const api = await start({
    env: enabledEnv(),
    fetchFn: async () => {
      called += 1
      throw new Error("network")
    },
    lookup: async () => {
      called += 1
      return []
    },
  })
  try {
    const res = await fetch(`${api.base}/v1/balances`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ address: key, chains: ["base"] }),
    })
    assert.equal(res.status, 400)
    const text = await res.text()
    assert.equal(text.includes("secrets_not_accepted"), true)
    assert.equal(text.toLowerCase().includes(key.slice(2).toLowerCase()), false)
    assert.equal(called, 0)
  } finally {
    await api.close()
  }
})

test("включённый x402 без адреса получателя не стартует", () => {
  assert.throws(() => createApiServer({ env: { X402_ENABLED: "true" } }))
})
