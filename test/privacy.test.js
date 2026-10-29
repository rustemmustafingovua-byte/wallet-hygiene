import { test } from "node:test"
import assert from "node:assert/strict"
import { readdirSync, readFileSync, statSync } from "node:fs"
import { join } from "node:path"
import { generatePrivateKey } from "viem/accounts"
import { balancesAt } from "../src/balances.js"
import {
  createGuardedFetch,
  registerSecret,
  resetSecretRegistry,
  sealEnvironmentSecrets,
  SecretEgressError,
} from "../src/privacy.js"

function sourceFiles(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) sourceFiles(path, out)
    else if (name.endsWith(".js")) out.push(path)
  }
  return out
}

test("исходники не содержат телеметрию и прямой fetch", () => {
  const banned = ["DASHBOARD_WEBHOOK", "webhook/wallet-hygiene", "pushDashboardStats", "http.request", "https.request"]
  const files = [...sourceFiles("src"), ...sourceFiles("bin")]
  assert.ok(files.length > 5)
  for (const file of files) {
    const text = readFileSync(file, "utf8")
    for (const needle of banned) {
      assert.equal(text.includes(needle), false, `${file} contains ${needle}`)
    }
    if (file.endsWith(`${join("src", "privacy.js")}`)) continue
    assert.equal(/\bfetch\s*\(/.test(text), false, `${file} calls fetch directly`)
  }
})

test("запрос баланса уходит на RPC выбранной сети и не содержит ключ", async () => {
  resetSecretRegistry()
  const privateKey = generatePrivateKey()
  registerSecret(privateKey)
  const calls = []
  const fetchFn = async (url, init) => {
    calls.push({ url: String(url), body: String(init?.body ?? "") })
    const req = JSON.parse(init.body)
    assert.equal(req.method, "eth_getBalance")
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: "0x0" }), {
      headers: { "content-type": "application/json" },
    })
  }
  const address = `0x${"a".repeat(40)}`
  const balances = await balancesAt("eth", address, [], { fetchFn })
  assert.equal(balances[0].amount, 0n)
  assert.equal(calls.length, 1)
  assert.match(calls[0].url, /ethereum-rpc\.publicnode\.com/)
  assert.equal(calls[0].url.includes("mainnet.base.org"), false)
  assert.equal(calls[0].body.toLowerCase().includes(privateKey.slice(2).toLowerCase()), false)
  assert.match(calls[0].body, new RegExp(address, "i"))
})

test("переопределение RPC читается из окружения, ключ в URL запрещён", async () => {
  resetSecretRegistry()
  const calls = []
  const fetchFn = async (url, init) => {
    calls.push(String(url))
    const req = JSON.parse(init.body)
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: req.id, result: "0x1" }), {
      headers: { "content-type": "application/json" },
    })
  }
  await balancesAt("base", `0x${"b".repeat(40)}`, [], {
    fetchFn,
    env: { WALLET_HYGIENE_RPC_BASE: "https://rpc.example/base" },
  })
  assert.equal(calls[0], "https://rpc.example/base")
  const guarded = createGuardedFetch(fetchFn)
  const key = generatePrivateKey()
  registerSecret(key)
  await assert.rejects(() => guarded(`https://rpc.example/${key}`, { method: "POST", body: "{}" }), SecretEgressError)
})

test("фасилитаторский токен-ключ не принимается, ключ из окружения не уходит в fetch", async () => {
  const key = generatePrivateKey()
  assert.throws(() => sealEnvironmentSecrets({ X402_FACILITATOR_AUTH: key }))
  assert.doesNotThrow(() => sealEnvironmentSecrets({ X402_FACILITATOR_AUTH: "facilitator-token" }))
  resetSecretRegistry()
  sealEnvironmentSecrets({ WALLET_HYGIENE_KEYS: JSON.stringify({ [`0x${"c".repeat(40)}`]: key }) })
  await assert.rejects(
    () => createGuardedFetch(async () => new Response("no"))("https://rpc.example", { method: "POST", body: key }),
    SecretEgressError,
  )
})
