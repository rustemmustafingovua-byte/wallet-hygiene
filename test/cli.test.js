import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { run } from "../src/cli.js"

function capture() {
  const lines = []
  return { lines, log: (s = "") => lines.push(String(s)), err: (s = "") => lines.push(String(s)) }
}

const KEY = `0x${"d".repeat(63)}1`

test("справка не ходит в сеть", async () => {
  let called = 0
  const prev = globalThis.fetch
  globalThis.fetch = () => {
    called += 1
    throw new Error("network")
  }
  try {
    const io = capture()
    const code = await run([], { env: {}, ...io })
    assert.equal(code, 0)
    assert.match(io.lines.join("\n"), /keys/)
    assert.match(io.lines.join("\n"), /подбирать ключи к чужим кошелькам он не умеет/)
    assert.equal(called, 0)
  } finally {
    globalThis.fetch = prev
  }
})

test("поиск ключей локальный и не печатает сам ключ", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-cli-"))
  writeFileSync(join(dir, "wallet.json"), JSON.stringify({ privateKey: KEY }))
  let called = 0
  const prev = globalThis.fetch
  globalThis.fetch = () => {
    called += 1
    throw new Error("network")
  }
  try {
    const io = capture()
    const code = await run(["keys", "--root", dir, "--no-git"], { env: {}, ...io })
    assert.equal(code, 0)
    const text = io.lines.join("\n")
    assert.match(text, /private-key/)
    assert.equal(text.includes(KEY), false)
    assert.equal(called, 0)
  } finally {
    globalThis.fetch = prev
  }
})

test("forgotten показывает остаток через подставленный клиент и не зовёт сеть", async () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-forgot-"))
  const address = `0x${"e".repeat(40)}`
  writeFileSync(join(dir, "note.txt"), `sent from ${address}`)
  let called = 0
  const prev = globalThis.fetch
  globalThis.fetch = () => {
    called += 1
    throw new Error("network")
  }
  try {
    const io = capture()
    const code = await run(["forgotten", "--root", dir, "--no-git", "--chains", "base"], {
      env: {},
      ...io,
      balancesAt: async () => [{ symbol: "ETH", decimals: 18, amount: 1_500_000_000_000_000_000n }],
    })
    assert.equal(code, 0)
    const text = io.lines.join("\n")
    assert.match(text, new RegExp(address, "i"))
    assert.match(text, /1\.5/)
    assert.equal(called, 0)
  } finally {
    globalThis.fetch = prev
  }
})

test("serve поднимается и сообщает, что оплата выключена", async () => {
  const io = capture()
  const code = await run(["serve", "--port", "0"], {
    env: {},
    serveHold: false,
    ...io,
    lookup: async () => [],
  })
  assert.equal(code, 0)
  assert.match(io.lines.join("\n"), /x402 выключен/)
})
