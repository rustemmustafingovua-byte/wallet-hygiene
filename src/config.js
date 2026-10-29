import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"
import { isAddress } from "./address.js"
import { registerSecret, userInputHasSecret } from "./privacy.js"

export function configDir(env = process.env) {
  return env.WALLET_HYGIENE_CONFIG_DIR || join(homedir(), ".config", "wallet-hygiene")
}

export function configPath(env = process.env) {
  return join(configDir(env), "config.json")
}

function readRaw(env) {
  const file = configPath(env)
  if (!existsSync(file)) return null
  try {
    return JSON.parse(readFileSync(file, "utf8"))
  } catch {
    return null
  }
}

export function loadConfig(env = process.env) {
  const raw = readRaw(env) ?? {}
  const fromEnv = env.WALLET_HYGIENE_MAIN || env.WALLET_MAIN || null
  const main = typeof raw.main === "string" ? raw.main : fromEnv
  return {
    main: main ? String(main).toLowerCase() : null,
    allowlist: Array.isArray(raw.allowlist) ? raw.allowlist : [],
    keysIgnored: Boolean(raw.keys),
  }
}

/**
 * Persist main and allowlist only. A file that already holds keys is left
 * untouched so the only copy of a key is not deleted out from under the owner.
 */
export function saveConfig(cfg, env = process.env) {
  const raw = readRaw(env)
  if (raw?.keys) {
    throw new Error("config.json contains keys; move them to a 0600 key file before rewriting config")
  }
  const dir = configDir(env)
  mkdirSync(dir, { recursive: true })
  const prev = loadConfig(env)
  const main = (cfg.main ?? prev.main ?? null)
  const next = {
    main: main ? String(main).toLowerCase() : null,
    allowlist: cfg.allowlist ?? prev.allowlist ?? [],
  }
  const file = configPath(env)
  writeFileSync(file, `${JSON.stringify(next, null, 2)}\n`, { mode: 0o600 })
  chmodSync(file, 0o600)
  return file
}

function absorb(map, parsed) {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("key map must be a JSON object of address to private key")
  }
  for (const [addr, key] of Object.entries(parsed)) {
    if (!isAddress(addr)) throw new Error("key map address is invalid")
    if (typeof key !== "string" || !/^0x[a-fA-F0-9]{64}$/.test(key)) {
      throw new Error("key map value is not a 32-byte hex private key")
    }
    registerSecret(key)
    map.set(addr.toLowerCase(), key)
  }
}

export function readAllowlist(file) {
  const text = readFileSync(file, "utf8")
  if (userInputHasSecret(text)) throw new Error("allowlist contains a secret; it must list addresses only")
  const parsed = JSON.parse(text)
  const list = Array.isArray(parsed) ? parsed : parsed?.addresses
  if (!Array.isArray(list) || list.length === 0) throw new Error("allowlist is empty")
  return list.map((entry) => {
    if (!isAddress(entry)) throw new Error("allowlist entry is not an address")
    return entry.toLowerCase()
  })
}

/** Local keys. Environment overrides the key file for the same address. */
export function loadKeyMap(env = process.env) {
  const map = new Map()
  const file = env.WALLET_HYGIENE_KEYFILE
  if (file) {
    if (!existsSync(file)) throw new Error("WALLET_HYGIENE_KEYFILE does not exist")
    const mode = statSync(file).mode & 0o777
    if ((mode & 0o077) !== 0) throw new Error("WALLET_HYGIENE_KEYFILE must be mode 0600")
    absorb(map, parseKeyJson(readFileSync(file, "utf8"), "WALLET_HYGIENE_KEYFILE"))
  }
  if (env.WALLET_HYGIENE_KEYS) absorb(map, parseKeyJson(env.WALLET_HYGIENE_KEYS, "WALLET_HYGIENE_KEYS"))
  return map
}

function parseKeyJson(text, label) {
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`${label} is not valid JSON`)
  }
}
