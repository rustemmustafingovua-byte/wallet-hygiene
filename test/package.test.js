import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"

test("package.json — валидный JSON, скрипт build не ломает npm ci", () => {
  const raw = readFileSync(new URL("../package.json", import.meta.url), "utf8")
  const pkg = JSON.parse(raw)
  assert.equal(typeof pkg.scripts.build, "string")
  assert.equal(typeof pkg.scripts.test, "string")
  assert.match(pkg.scripts.test, /node --test/)
  assert.equal(pkg.engines.node, ">=20")
  assert.equal(pkg.bin["wallet-hygiene"], "bin/wallet-hygiene.js")
})
