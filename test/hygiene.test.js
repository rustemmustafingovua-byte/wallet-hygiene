import { test } from "node:test"
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import {
  findKeyLeaks,
  findOwnAddresses,
  isKnownConstant,
  KNOWN_DEV_KEYS,
  KNOWN_TOKEN_ADDRESSES,
  resetSecretRegistry,
  walk,
} from "../src/index.js"

const KEY = `0x${"a".repeat(63)}1`
const DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

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
  assert.ok(!files.includes("c.txt"))
})

test("закрытый ключ рядом со словом private — находка, но не полный секрет", () => {
  resetSecretRegistry()
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  writeFileSync(join(dir, "w.json"), JSON.stringify({ privateKey: KEY, address: "0x1" }))
  const findings = findKeyLeaks([dir])
  assert.equal(findings.length, 1)
  assert.equal(findings[0].id, "private-key")
  assert.equal(JSON.stringify(findings).includes(KEY), false)
  assert.equal(JSON.stringify(findings).includes(KEY.slice(2)), false)
})

test("64-hex константа без контекста — не находка", () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  writeFileSync(join(dir, "c.sol"), "uint256 constant MAX = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF;")
  assert.equal(findKeyLeaks([dir]).length, 0)
})

test("известные константы и dev-ключи отсекаются", () => {
  resetSecretRegistry()
  assert.equal(isKnownConstant("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"), true)
  assert.equal(isKnownConstant(`0x${"0".repeat(64)}`), true)
  assert.equal(isKnownConstant(KEY), false)
  assert.ok(KNOWN_DEV_KEYS.has(DEV_KEY))
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  writeFileSync(join(dir, "hardhat.json"), JSON.stringify({ privateKey: DEV_KEY }))
  assert.equal(findKeyLeaks([dir]).length, 0)
})

test("seed-фраза ловится только рядом со словом seed", () => {
  resetSecretRegistry()
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  writeFileSync(join(dir, "plain.md"), "the quick brown fox jumps over the lazy dog and runs away")
  assert.equal(findKeyLeaks([dir]).length, 0)
  writeFileSync(join(dir, "s.md"), "seed phrase: legal winner thank year wave sausage worth useful legal winner thank yellow")
  const findings = findKeyLeaks([dir])
  assert.ok(findings.some((f) => f.id === "seed-phrase"))
  assert.equal(JSON.stringify(findings).includes("legal winner thank year"), false)
})

test("токен доступа распознаётся и не возвращается целиком", () => {
  resetSecretRegistry()
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
  writeFileSync(join(dir, ".env"), `GITHUB_TOKEN=${token}`)
  const findings = findKeyLeaks([dir])
  assert.ok(findings.some((f) => f.id === "bearer"))
  assert.equal(JSON.stringify(findings).includes(token), false)
})

test("свои адреса находятся и привязаны к источникам", () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-"))
  const addr = `0x${"b".repeat(40)}`
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
  const usdc = [...KNOWN_TOKEN_ADDRESSES][0]
  writeFileSync(join(dir, "tokens.txt"), `USDC: ${usdc}`)
  assert.equal(findOwnAddresses([dir]).length, 0)
})

test("ключ, удалённый из рабочего дерева, всё ещё виден в git-истории", () => {
  resetSecretRegistry()
  const dir = mkdtempSync(join(tmpdir(), "wh-git-"))
  const git = (args) => execFileSync("git", ["-C", dir, ...args], { stdio: ["ignore", "pipe", "pipe"] })
  git(["init"])
  git(["config", "user.email", "wallet-hygiene@example.com"])
  git(["config", "user.name", "wallet-hygiene"])
  writeFileSync(join(dir, "note.txt"), `privateKey=${KEY}`)
  git(["add", "note.txt"])
  git(["-c", "commit.gpgsign=false", "commit", "-m", "add key"])
  rmSync(join(dir, "note.txt"))
  git(["add", "note.txt"])
  git(["-c", "commit.gpgsign=false", "commit", "-m", "remove key"])
  assert.equal(findKeyLeaks([dir]).length, 0)
  const findings = findKeyLeaks([dir], { git: true })
  assert.ok(findings.some((f) => f.id === "private-key" && f.tracked))
  assert.equal(JSON.stringify(findings).includes(KEY), false)
})
