import { test } from "node:test"
import assert from "node:assert/strict"
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import { run } from "../src/cli.js"
import { NATIVE_GAS, FEE_RESERVE_MULTIPLIER, planNativeSweep, sweepOne } from "../src/sweep.js"
import { createGuardedFetch, resetSecretRegistry, SecretEgressError } from "../src/privacy.js"

function capture() {
  const lines = []
  return { lines, log: (s = "") => lines.push(String(s)), err: (s = "") => lines.push(String(s)) }
}

function mockClient(balance, sent) {
  return {
    getBalance: async () => balance,
    estimateFeesPerGas: async () => ({ maxFeePerGas: 1_000_000_000n, maxPriorityFeePerGas: 1_000_000n }),
    getTransactionCount: async () => 0,
    sendRawTransaction: async ({ serializedTransaction }) => {
      sent.push(serializedTransaction)
      return `0x${"ab".repeat(32)}`
    },
  }
}

test("план оставляет резерв на газ и не уходит в минус", () => {
  const fee = 1_000_000_000n
  const balance = 2_000_000_000_000_000_000n
  const plan = planNativeSweep({ balance, maxFeePerGas: fee })
  const reserve = NATIVE_GAS * fee * FEE_RESERVE_MULTIPLIER
  assert.equal(plan.skip, false)
  assert.equal(plan.reserve, reserve)
  assert.equal(plan.value, balance - reserve)
  const poor = planNativeSweep({ balance: reserve, maxFeePerGas: fee })
  assert.equal(poor.skip, true)
  assert.equal(poor.value, 0n)
})

test("подпись локальная: в транзакцию и в сеть не попадает приватный ключ", async () => {
  resetSecretRegistry()
  const privateKey = generatePrivateKey()
  const from = privateKeyToAccount(privateKey).address
  const to = `0x${"2".repeat(40)}`
  const sent = []
  const result = await sweepOne({
    chainKey: "base",
    from,
    to,
    execute: true,
    privateKey,
    client: mockClient(2_000_000_000_000_000_000n, sent),
  })
  assert.equal(sent.length, 1)
  assert.equal(result.hash, `0x${"ab".repeat(32)}`)
  assert.equal(sent[0].toLowerCase().includes(privateKey.slice(2).toLowerCase()), false)
  const calls = []
  const fetchFn = createGuardedFetch(async (_url, init) => {
    calls.push(String(init.body))
    return new Response("ok")
  })
  await fetchFn("https://rpc.example", { method: "POST", body: sent[0] })
  await assert.rejects(
    () => fetchFn("https://rpc.example", { method: "POST", body: JSON.stringify({ privateKey }) }),
    SecretEgressError,
  )
  assert.equal(calls.length, 1)
  assert.equal(calls[0].includes(privateKey.slice(2)), false)
})

test("sweep --yes подписывает только allowlist и пишет план без ключа в логе", async () => {
  resetSecretRegistry()
  const privateKey = generatePrivateKey()
  const from = privateKeyToAccount(privateKey).address.toLowerCase()
  const to = `0x${"3".repeat(40)}`
  const dir = mkdtempSync(join(tmpdir(), "wh-sweep-"))
  const allow = join(dir, "allow.json")
  const keyFile = join(dir, "keys.json")
  writeFileSync(allow, JSON.stringify([from]))
  writeFileSync(keyFile, JSON.stringify({ [from]: privateKey }))
  chmodSync(keyFile, 0o600)
  const sent = []
  const env = {
    WALLET_HYGIENE_CONFIG_DIR: dir,
    WALLET_HYGIENE_KEYFILE: keyFile,
  }
  const io = capture()
  const code = await run(["init", "--main", to], { env, ...io })
  assert.equal(code, 0)
  const exec = await run(["sweep", "--allowlist", allow, "--to", to, "--chains", "base", "--yes"], {
    env,
    ...io,
    clientFor: () => mockClient(2_000_000_000_000_000_000n, sent),
  })
  assert.equal(exec, 0)
  assert.equal(sent.length, 1)
  const text = io.lines.join("\n")
  assert.equal(text.toLowerCase().includes(privateKey.slice(2).toLowerCase()), false)
  assert.match(text, /tx 0xabab/)
})

test("без --yes транзакция не отправляется", async () => {
  const from = `0x${"4".repeat(40)}`
  const to = `0x${"5".repeat(40)}`
  const dir = mkdtempSync(join(tmpdir(), "wh-plan-"))
  const allow = join(dir, "allow.json")
  writeFileSync(allow, JSON.stringify([from]))
  const sent = []
  const io = capture()
  const code = await run(["sweep", "--allowlist", allow, "--to", to, "--chains", "base"], {
    env: { WALLET_HYGIENE_CONFIG_DIR: dir },
    ...io,
    clientFor: () => mockClient(2_000_000_000_000_000_000n, sent),
  })
  assert.equal(code, 0)
  assert.equal(sent.length, 0)
  assert.match(io.lines.join("\n"), /это план/)
})

test("--yes без init и чужой --to не отправляют транзакцию", async () => {
  const from = `0x${"6".repeat(40)}`
  const saved = `0x${"7".repeat(40)}`
  const other = `0x${"8".repeat(40)}`
  const dir = mkdtempSync(join(tmpdir(), "wh-guard-"))
  const allow = join(dir, "allow.json")
  writeFileSync(allow, JSON.stringify([from]))
  const sent = []
  const env = { WALLET_HYGIENE_CONFIG_DIR: dir }
  const clientFor = () => mockClient(2_000_000_000_000_000_000n, sent)
  const noInit = await run(["sweep", "--allowlist", allow, "--to", saved, "--chains", "base", "--yes"], {
    env,
    ...capture(),
    clientFor,
  })
  assert.equal(noInit, 2)
  await run(["init", "--main", saved], { env, ...capture() })
  const mismatch = await run(["sweep", "--allowlist", allow, "--to", other, "--chains", "base", "--yes"], {
    env,
    ...capture(),
    clientFor,
  })
  assert.equal(mismatch, 2)
  assert.equal(sent.length, 0)
})
