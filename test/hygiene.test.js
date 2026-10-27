import { test } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { findKeyLeaks, findOwnAddresses, walk, isKnownConstant, KNOWN_DEV_KEYS, KNOWN_TOKEN_ADDRESSES } from "../bin/wallet-hygiene.js"

const KEY = "0x" + "a".repeat(63) + "1"

test("walk обходит дерево и пропускает node_modules", () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  mkdirSync(join(dir, "sub"), { recursive: true })
  mkdirSync(join(dir, "node_modules", "x"), { recursive: true })
  writeFileSync(join(dir, "a.txt"), "hello")
  writeFileSync(join(dir, "sub", "b.md"), "world")
  writeFileSync(join(dir, "node_modules", "x", "c.txt"), "skip me")
  const files = [...walk(dir)].map((f) => f.split("/").pop())
  assert.ok(files.includes("a.txt"))
  assert.ok(files.includes("b.md"))
  assert.ok(!files.includes("c.txt"), "node_modules должен пропускаться")
})

test("закрытый ключ рядом со словом private — находка", () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  writeFileSync(join(dir, "w.json"), JSON.stringify({ privateKey: KEY, address: "0x1" }))
  const findings = findKeyLeaks([dir])
  assert.equal(findings.length, 1)
  assert.equal(findings[0].id, "private-key")
})

test("64-hex константа без контекста — не находка", () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  writeFileSync(join(dir, "c.sol"), "uint256 constant MAX = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;")
  assert.equal(findKeyLeaks([dir]).length, 0)
})

test("известные константы и dev-ключи отсекаются", () => {
  assert.equal(isKnownConstant("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"), true)
  assert.equal(isKnownConstant("0x" + "0".repeat(64)), true)
  assert.equal(isKnownConstant(KEY), false)
  assert.ok(KNOWN_DEV_KEYS.size > 0)
})

test("seed-фраза ловится только рядом со словом seed", () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  writeFileSync(join(dir, "plain.md"), "the quick brown fox jumps over the lazy dog and runs away")
  assert.equal(findKeyLeaks([dir]).length, 0, "обычный текст — не seed")
  writeFileSync(join(dir, "s.md"), "seed phrase: legal winner thank year wave sausage worth useful legal winner thank yellow")
  assert.ok(findKeyLeaks([dir]).some((f) => f.id === "seed-phrase"))
})

test("токен доступа распознаётся", () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  writeFileSync(join(dir, ".env"), "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789")
  const findings = findKeyLeaks([dir])
  assert.ok(findings.some((f) => f.id === "bearer"))
})

test("свои адреса находятся и привязаны к источникам", () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  const addr = "0x" + "b".repeat(40)
  writeFileSync(join(dir, "note.txt"), `used ${addr} yesterday`)
  const found = findOwnAddresses([dir])
  assert.equal(found.length, 1)
  assert.equal(found[0].address, addr.toLowerCase())
  assert.ok(found[0].sources.length > 0)
})

test("пустая директория не ломает поиск", () => {
  assert.equal(findKeyLeaks(["/nope/not/here"]).length, 0)
  assert.equal(findOwnAddresses(["/nope/not/here"]).length, 0)
})

test("известные токен-контракты не попадают в забытые адреса", () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  writeFileSync(join(dir, "tokens.txt"), "USDC: 0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")
  const found = findOwnAddresses([dir])
  assert.equal(found.length, 0, "USDC контракт не должен быть в забытых адресах")
})
