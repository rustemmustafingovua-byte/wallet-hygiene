import { test } from "node:test"
import assert from "node:assert/strict"
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts"
import { loadConfig, loadKeyMap, saveConfig } from "../src/config.js"
import { createGuardedFetch, resetSecretRegistry, SecretEgressError } from "../src/privacy.js"

test("конфиг хранит только адрес и создаётся с правами 0600", () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-cfg-"))
  const env = { WALLET_HYGIENE_CONFIG_DIR: dir }
  const main = `0x${"a".repeat(40)}`
  const file = saveConfig({ main, keys: { [main]: generatePrivateKey() } }, env)
  const mode = statSync(file).mode & 0o777
  assert.equal(mode, 0o600)
  const saved = JSON.parse(readFileSync(file, "utf8"))
  assert.equal(saved.main, main)
  assert.equal("keys" in saved, false)
  assert.equal(loadConfig(env).keysIgnored, false)
})

test("существующее поле keys не перезаписывается и не читается как ключ для sweep", () => {
  const dir = mkdtempSync(join(tmpdir(), "wh-cfg-keys-"))
  const file = join(dir, "config.json")
  const main = `0x${"b".repeat(40)}`
  const privateKey = generatePrivateKey()
  writeFileSync(file, JSON.stringify({ main, keys: { [main]: privateKey } }))
  const env = { WALLET_HYGIENE_CONFIG_DIR: dir }
  assert.equal(loadConfig(env).keysIgnored, true)
  assert.throws(() => saveConfig({ main }, env), /contains keys/)
  assert.equal(readFileSync(file, "utf8").includes(privateKey), true)
  assert.equal(loadKeyMap(env).size, 0)
})

test("файл ключей обязан быть 0600, и загруженный ключ нельзя отправить", async () => {
  resetSecretRegistry()
  const dir = mkdtempSync(join(tmpdir(), "wh-keys-"))
  const file = join(dir, "keys.json")
  const privateKey = generatePrivateKey()
  const address = privateKeyToAccount(privateKey).address
  writeFileSync(file, JSON.stringify({ [address]: privateKey }))
  chmodSync(file, 0o644)
  const env = { WALLET_HYGIENE_KEYFILE: file }
  assert.throws(() => loadKeyMap(env), /0600/)
  chmodSync(file, 0o600)
  const map = loadKeyMap(env)
  assert.equal(map.get(address.toLowerCase()), privateKey)
  await assert.rejects(
    () => createGuardedFetch(async () => new Response("no"))("https://rpc.example", {
      method: "POST",
      body: JSON.stringify({ k: privateKey }),
    }),
    SecretEgressError,
  )
})
