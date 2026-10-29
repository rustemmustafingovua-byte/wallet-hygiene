import { execFileSync } from "node:child_process"
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs"
import { extname, join } from "node:path"
import { registerSecret } from "./privacy.js"

const SECRET_PATTERNS = [
  { id: "private-key", re: /0x[a-fA-F0-9]{64}/g, why: "закрытый ключ в открытом виде" },
  { id: "bearer", re: /\b(?:ghp|gho|github_pat|npm)_[A-Za-z0-9_]{20,}\b/g, why: "токен доступа" },
]

/** Public Anvil/Hardhat keys. They are not a leak. */
export const KNOWN_DEV_KEYS = new Set([
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
  "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
  "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
  "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
  "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
  "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
  "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
  "0xf214f2b2cd398c806f84e317254e0f0b801d0643303237d97a22a48e01628897",
  "0x701b615bbdfb9de65240bc28bd21bbc0d996645a3dd57e7b12bc2bdf6f192c82",
  "0xa267530f49f8280200edf313ee7af6b827f2a8bce2897751d4415b1542cf2b1c",
  "0x47c99abed3324a2707c28affff1267e45918ec8c3f20b8aa892e8b065d2942cb",
])

/** Token contracts are not forgotten wallets. */
export const KNOWN_TOKEN_ADDRESSES = new Set([
  "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", // USDC (Base)
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC (Ethereum)
  "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT (Ethereum)
  "0x6b175474e89094c44da98b954eedeac495271d0f", // DAI (Ethereum)
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // WETH (Ethereum)
  "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", // WBTC (Ethereum)
  "0x4200000000000000000000000000000000000006", // WETH (Base / OP)
  "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619", // WETH (Polygon)
])

const VENDOR_PATH = /[\\/](lib|node_modules|vendor|testdata|fixtures)[\\/]/i
const SEED_CONTEXT = /seed|mnemonic|recovery phrase|keystore|derivation path/i
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "out", "build", ".next", "cache", "vendor"])
const TEXT_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".json", ".md", ".txt", ".env", ".yml", ".yaml", ".sh", ".py", ".toml", ".log", ".sol"])

export function isKnownConstant(value) {
  const v = String(value).toLowerCase()
  const known = new Set([
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
    "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "0x0000000000000000000000000000000000000000000000000000000000000001",
  ])
  if (known.has(v)) return true
  if (/^0x[0]{20,}/.test(v)) return true
  if (/^0x[f]{20,}/.test(v)) return true
  return false
}

export function* walk(dir, depth = 0) {
  if (depth > 6) return
  let entries
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return
  }
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== ".env") continue
    const full = join(dir, e.name)
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue
      yield* walk(full, depth + 1)
    } else if (e.isFile()) {
      const ext = extname(e.name) || (e.name === ".env" ? ".env" : "")
      if (TEXT_EXT.has(ext) || e.name === ".env") yield full
    }
  }
}

function readText(file) {
  try {
    const st = statSync(file)
    if (st.size > 2_000_000) return ""
    return readFileSync(file, "utf8")
  } catch {
    return ""
  }
}

function execSafe(cmd, args) {
  try {
    return execFileSync(cmd, args, {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    })
  } catch {
    return ""
  }
}

export function isTrackedByGit(file) {
  let dir = file.slice(0, Math.max(file.lastIndexOf("/"), file.lastIndexOf("\\")))
  for (let i = 0; i < 8 && dir; i++) {
    if (existsSync(join(dir, ".git"))) {
      const out = execSafe("git", ["-C", dir, "ls-files", "--error-unmatch", "--", file])
      return out.trim().length > 0
    }
    const parent = dir.slice(0, Math.max(dir.lastIndexOf("/"), dir.lastIndexOf("\\")))
    if (parent === dir) break
    dir = parent
  }
  return false
}

function sampleOf(value) {
  const s = String(value)
  if (s.length <= 16) return "…"
  return `${s.slice(0, 8)}…${s.slice(-4)}`
}

function scanText(file, content, findings, { tracked = false } = {}) {
  if (!content) return
  for (const p of SECRET_PATTERNS) {
    let from = 0
    for (const m of content.match(p.re) ?? []) {
      const idx = content.indexOf(m, from)
      if (idx < 0) continue
      from = idx + m.length
      if (isKnownConstant(m)) continue
      if (p.id === "private-key" && KNOWN_DEV_KEYS.has(m.toLowerCase())) continue
      const around = content.slice(Math.max(0, idx - 160), idx + m.length + 160)
      if (p.id === "private-key" && !/private|secret|signer|mnemonic|wallet|key\b/i.test(around)) continue
      registerSecret(m)
      findings.push({
        file,
        id: p.id,
        why: p.why,
        sample: sampleOf(m),
        vendor: VENDOR_PATH.test(file),
        tracked,
      })
    }
  }
  if (SEED_CONTEXT.test(content)) {
    let from = 0
    for (const m of content.match(/\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b/gi) ?? []) {
      const idx = content.indexOf(m, from)
      if (idx < 0) continue
      from = idx + m.length
      const around = content.slice(Math.max(0, idx - 200), idx + m.length + 200)
      if (!SEED_CONTEXT.test(around)) continue
      registerSecret(m)
      findings.push({
        file,
        id: "seed-phrase",
        why: "похоже на seed-фразу",
        sample: sampleOf(m),
        vendor: VENDOR_PATH.test(file),
        tracked,
      })
    }
  }
}

export function findKeyLeaks(roots, { git = false } = {}) {
  const findings = []
  for (const root of roots) {
    if (!existsSync(root)) continue
    for (const file of walk(root)) scanText(file, readText(file), findings, { tracked: false })
    if (git && existsSync(join(root, ".git"))) {
      const patch = execSafe("git", ["-C", root, "log", "--all", "-p", "--no-color", "--"])
      scanText(`${root} (git history)`, patch, findings, { tracked: true })
    }
  }
  return findings
}

export function findOwnAddresses(roots, gitDirs = []) {
  const found = new Map()
  const re = /0x[a-fA-F0-9]{40}/g
  const add = (addr, src) => {
    const a = addr.toLowerCase()
    if (KNOWN_TOKEN_ADDRESSES.has(a)) return
    if (!found.has(a)) found.set(a, new Set())
    found.get(a).add(src)
  }
  for (const root of roots) {
    if (!existsSync(root)) continue
    for (const file of walk(root)) {
      const content = readText(file)
      for (const m of content.match(re) ?? []) add(m, file)
    }
  }
  for (const dir of gitDirs) {
    if (!existsSync(dir)) continue
    const out = execSafe("git", ["-C", dir, "log", "--all", "-p", "--no-color", "--"])
    for (const m of out.match(re) ?? []) add(m, `${dir} (git history)`)
  }
  return [...found.entries()].map(([address, sources]) => ({
    address,
    sources: [...sources].slice(0, 3),
  }))
}
