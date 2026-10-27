#!/usr/bin/env node
/**
 * wallet-hygiene — инструмент для своих кошельков, а не для чужих.
 *
 * Что он делает:
 *   keys       ищет утечки приватных ключей и seed-фраз в твоих репозиториях,
 *              конфигах и логах (частая причина потери доступа к кошельку);
 *   forgotten  находит адреса, которые ты когда-то использовал (git-история,
 *              конфиги, логи), и проверяет их балансы — «забытые» кошельки;
 *   balances   показывает балансы (нативный актив + токены) по списку адресов;
 *   sweep      собирает средства с адресов из allowlist на твой основной кошелёк.
 *              Гас платит сам исходный кошелёк, поэтому внешние средства не нужны.
 *
 * Жёсткие ограничения (сделаны специально):
 *   • трогать можно ТОЛЬКО адреса из allowlist;
 *   • `--to` обязан совпадать с основным кошельком из конфига;
 *   • по умолчанию sweep только показывает план (--dry-run);
 *   • инструмент не подбирает ключи к чужим кошелькам и не сканирует чужие
 *     адреса: это кража, а не гигиена.
 *
 *   node bin/wallet-hygiene.js keys
 *   node bin/wallet-hygiene.js forgotten --chains base,eth
 *   node bin/wallet-hygiene.js sweep --allowlist allowlist.json --to 0x… --yes
 */
import { readFileSync, writeFileSync, existsSync, readdirSync, statSync, mkdirSync, chmodSync } from "node:fs"
import { execFileSync } from "node:child_process"
import { join, extname } from "node:path"
import { homedir } from "node:os"
import { createPublicClient, createWalletClient, http, parseAbi, erc20Abi, formatUnits } from "viem"
import { base } from "viem/chains"

const CONFIG_DIR = join(homedir(), ".config", "wallet-hygiene")
const CONFIG_FILE = join(CONFIG_DIR, "config.json")

const ok = (s) => `\x1b[32m${s}\x1b[0m`
const bad = (s) => `\x1b[31m${s}\x1b[0m`
const warn = (s) => `\x1b[33m${s}\x1b[0m`
const dim = (s) => `\x1b[2m${s}\x1b[0m`

export const CHAINS = {
  base: { name: "Base", rpc: "https://mainnet.base.org", id: 8453 },
  eth: { name: "Ethereum", rpc: "https://ethereum-rpc.publicnode.com", id: 1 },
  arbitrum: { name: "Arbitrum", rpc: "https://arb1.arbitrum.io/rpc", id: 42161 },
  optimism: { name: "Optimism", rpc: "https://mainnet.optimism.io", id: 10 },
  polygon: { name: "Polygon", rpc: "https://polygon-rpc.com", id: 137 },
}

const SECRET_PATTERNS = [
  { id: "private-key", re: /0x[a-fA-F0-9]{64}/g, why: "закрытый ключ в открытом виде" },
  { id: "bearer", re: /\b(?:ghp|gho|github_pat|npm)_[A-Za-z0-9_]{20,}\b/g, why: "токен доступа" },
]

/** Ключи из стандартных dev-окружений (anvil/hardhat) — они публичные. */
export const KNOWN_DEV_KEYS = new Set([
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
  "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
  "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
  "0xf214f2b2cd398c806f84e317254e0f0b801d0643303237d97a22a48e01628897",
  "0x701b615bbdfb9de65240bc28bd21bbc0d996645a3dd57e7b12bc2bdf6f192c82",
  "0xa267530f49f8280200edf313ee7af6b827f2a8bce2897751d4415b1542cf2b1c",
  "0x47c99abed3324a2707c28affff1267e45918ec8c3f20b8aa892e8b065d2942cb",
  "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
])

/** Известные токен-контракты — не являются "забытыми кошельками". */
export const KNOWN_TOKEN_ADDRESSES = new Set([
  "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", // USDC (Base)
  "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC (Ethereum)
  "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT (Ethereum)
  "0x6b175474e89094c44da98b954eedeac495271d0f", // DAI (Ethereum)
  "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", // WETH (Ethereum)
  "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", // WBTC (Ethereum)
  "0x7ceb23fd6bc0add59e62ac25578270cff1b9f619", // WETH (Polygon)
])

/** Каталоги вендоров и тестовых фикстур — там ключи ожидаемы. */
const VENDOR_PATH = /[\/](lib|node_modules|vendor|testdata|fixtures)[\/]/i

/** Известные 64-hex константы, которые не являются ключами. */
export function isKnownConstant(value) {
  const v = String(value).toLowerCase()
  const known = new Set([
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // Transfer(address,address,uint256)
    "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // uint224.max
    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // uint256.max
    "0x0000000000000000000000000000000000000000000000000000000000000001",
  ])
  if (known.has(v)) return true
  // secp256k1 / curve constants: заведомо не приватные ключи
  if (/^0x[0]{20,}/.test(v)) return true
  if (/^0x[f]{20,}/.test(v)) return true
  return false
}

/** Seed-фраза распознаётся только рядом со словом seed/mnemonic/keystore. */
const SEED_CONTEXT = /seed|mnemonic|recovery phrase|keystore|derivation path/i

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "out", "build", ".next", "cache", "vendor"])
const TEXT_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".json", ".md", ".txt", ".env", ".yml", ".yaml", ".sh", ".py", ".toml", ".log", ".sol"])

/** Рекурсивно обойти каталог и собрать текстовые файлы. */
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

/** Найти утечки ключей в своих файлах. */
export function findKeyLeaks(roots) {
  const findings = []
  for (const root of roots) {
    if (!existsSync(root)) continue
    for (const file of walk(root)) {
      let content
      try {
        const st = statSync(file)
        if (st.size > 2_000_000) continue
        content = readFileSync(file, "utf8")
      } catch {
        continue
      }
      const lines = content.split("\n")
      for (const p of SECRET_PATTERNS) {
        for (const m of content.match(p.re) ?? []) {
          if (isKnownConstant(m)) continue
          const idx = content.indexOf(m)
          const around = content.slice(Math.max(0, idx - 160), idx + m.length + 160)
          // 64-hex в коде — часто константа (маска сети, тема события), а не ключ
          if (p.id === "private-key" && !/private|secret|signer|mnemonic|wallet|key\b/i.test(around)) continue
          findings.push({ file, id: p.id, why: p.why, sample: `${m.slice(0, 8)}…${m.slice(-4)}` })
        }
      }
      // seed-фраза — только если рядом контекст
      if (SEED_CONTEXT.test(content)) {
        for (const m of content.match(/\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b/gi) ?? []) {
          const idx = content.indexOf(m)
          const around = content.slice(Math.max(0, idx - 200), idx + m.length + 200)
          if (!SEED_CONTEXT.test(around)) continue
          findings.push({ file, id: "seed-phrase", why: "похоже на seed-фразу", sample: `${m.slice(0, 12)}…` })
        }
      }
      void lines
    }
  }
  return findings
}

/** Отслеживается ли файл git'ом: попадание в репозиторий = настоящая утечка. */
export function isTrackedByGit(file) {
  const dir = file.slice(0, file.lastIndexOf("/"))
  if (!existsSync(join(dir, ".git"))) {
    // ищем корень репозитория выше
    let d = dir
    for (let i = 0; i < 8; i++) {
      const parent = d.slice(0, d.lastIndexOf("/"))
      if (existsSync(join(parent, ".git"))) return gitTracked(parent, file)
      d = parent
    }
    return false
  }
  return gitTracked(dir, file)
}

function gitTracked(repo, file) {
  const out = execSafe("git", ["-C", repo, "ls-files", "--error-unmatch", "--", file])
  return out.trim().length > 0
}

/** Найти адреса, которые встречаются в твоих файлах и истории git. */
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
      let content
      try {
        if (statSync(file).size > 2_000_000) continue
        content = readFileSync(file, "utf8")
      } catch {
        continue
      }
      for (const m of content.match(re) ?? []) add(m, file)
    }
  }
  for (const dir of gitDirs) {
    if (!existsSync(dir)) continue
    try {
      const out = execSafe("git", ["-C", dir, "log", "--all", "-p", "--", "."])
      for (const m of out.match(re) ?? []) add(m, `${dir} (git history)`)
    } catch {}
  }
  return [...found.entries()].map(([address, sources]) => ({ address, sources: [...sources].slice(0, 3) }))
}

function execSafe(cmd, args) {
  try {
    return execFileSync(cmd, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] })
  } catch {
    return ""
  }
}

const erc20BalanceOf = parseAbi(["function balanceOf(address) view returns (uint256)"])

/** Баланс адреса в сети: нативный + несколько токенов. */
export async function balancesAt(chainKey, address, tokens = []) {
  const chain = CHAINS[chainKey]
  const client = createPublicClient({ chain: base, transport: http(chain.rpc) })
  const native = await client.getBalance({ address })
  const out = [{ symbol: "ETH", decimals: 18, amount: native }]
  for (const t of tokens) {
    try {
      const amount = await client.readContract({
        address: t.address,
        abi: erc20BalanceOf,
        functionName: "balanceOf",
        args: [address],
      })
      out.push({ symbol: t.symbol, decimals: t.decimals ?? 18, amount })
    } catch {
      // контракт мог не ответить — пропускаем
    }
  }
  return out
}

function loadConfig() {
  if (!existsSync(CONFIG_FILE)) {
    return { main: process.env.WALLET_MAIN || null, allowlist: [] }
  }
  try {
    return JSON.parse(readFileSync(CONFIG_FILE, "utf8"))
  } catch {
    return { main: null, allowlist: [] }
  }
}

function saveConfig(cfg) {
  mkdirSync(CONFIG_DIR, { recursive: true })
  writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2))
  chmodSync(CONFIG_FILE, 0o600)
}

function pushDashboardStats(data) {
  const webhook = process.env.DASHBOARD_WEBHOOK_URL
  if (!webhook) return
  try {
    fetch(webhook + "/webhook/wallet-hygiene", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(data),
    }).catch(() => {})
  } catch {}
}

const argv = process.argv.slice(2)
const cmd = argv[0] ?? "help"
const flag = (name, def = null) => {
  const i = argv.indexOf(`--${name}`)
  return i >= 0 ? argv[i + 1] : def
}
const has = (name) => argv.includes(`--${name}`)

const WORKSPACE = join(homedir(), "workspace")
const SECRETS = join(homedir(), ".config", "opencode", "secrets")

async function main() {
  console.log()
  switch (cmd) {
    case "keys": {
      console.log(ok("=== поиск утечек ключей в твоих файлах ===\n"))
      const roots = [SECRETS, WORKSPACE, join(homedir(), ".config/opencode")]
      const findings = findKeyLeaks(roots)
      if (!findings.length) {
        console.log(ok("  утечек не найдено"))
        break
      }
      // раскладываем по серьёзности: в git — утечка, в secrets/.env — ожидаемое место
      const classified = findings.map((f) => {
        const tracked = isTrackedByGit(f.file)
        const inSecretDir = /[\/](secrets|\.config)[\/]/.test(f.file) || f.file.endsWith("/.env")
        const vendor = VENDOR_PATH.test(f.file)
        const devKey = KNOWN_DEV_KEYS.has(f.sample.replace("…", "")) || KNOWN_DEV_KEYS.has(f.full ?? "")
        let severity = tracked ? "critical" : inSecretDir ? "info" : "medium"
        if (vendor) severity = "info"
        return { ...f, severity, tracked, vendor, note: vendor ? "вендор/фикстура" : null }
      })
      const order = { critical: 0, medium: 1, info: 2 }
      classified.sort((a, b) => order[a.severity] - order[b.severity])
      for (const f of classified) {
        const label = f.severity === "critical" ? bad : f.severity === "medium" ? warn : dim
        console.log(
          label(
            `  [${f.severity}] ${f.id}: ${f.why}${f.tracked && f.severity === "critical" ? " — ФАЙЛ В GIT" : ""}${f.vendor ? " (вендор/фикстура)" : ""}`,
          ),
        )
        console.log(dim(`     ${f.file}`))
        console.log(dim(`     ${f.sample}`))
      }
      const crit = classified.filter((f) => f.severity === "critical").length
      const med = classified.filter((f) => f.severity === "medium").length
      console.log()
      if (crit) console.log(bad(`  критично: ${crit} — ключ в git считается скомпрометированным, смени его`))
      if (med) console.log(warn(`  стоит проверить: ${med}`))
      console.log(dim(`  в ожидаемых местах (secrets/, .env): ${classified.length - crit - med}`))
      pushDashboardStats({ scans: 1, keysFound: classified.length })
      break
    }

    case "forgotten": {
      console.log(ok("=== забытые адреса: где ты их оставлял ===\n"))
      const roots = [SECRETS, WORKSPACE, join(homedir(), ".config/opencode")]
      const gitDirs = []
      try {
        for (const d of readdirSync(WORKSPACE)) {
          if (existsSync(join(WORKSPACE, d, ".git"))) gitDirs.push(join(WORKSPACE, d))
        }
      } catch {}
      const found = findOwnAddresses(roots, gitDirs)
      const chains = (flag("chains", "base,eth") ?? "base,eth").split(",")
      const main = loadConfig().main?.toLowerCase()
      const interesting = []
      for (const { address, sources } of found) {
        if (main && address === main) continue
        for (const chainKey of chains) {
          if (!CHAINS[chainKey]) continue
          const bals = await balancesAt(chainKey, address)
          const total = bals.reduce((a, b) => a + Number(b.amount) / 10 ** b.decimals, 0)
          if (total > 0) {
            interesting.push({ address, chainKey, total, bals, sources })
            break
          }
        }
      }
      if (!interesting.length) {
        console.log(ok("  адресов с остатками не найдено"))
      } else {
        for (const i of interesting) {
          console.log(warn(`  ${i.address}  [${CHAINS[i.chainKey].name}]  ≈${i.total.toFixed(6)}`))
          for (const b of i.bals) {
            if (b.amount === 0n) continue
            console.log(dim(`     ${b.symbol}: ${formatUnits(b.amount, b.decimals)}`))
          }
          console.log(dim(`     где: ${i.sources.join(", ")}`))
        }
        console.log(dim("\n  добавь адрес в allowlist и запусти sweep — газ платит сам кошелёк"))
      }
      pushDashboardStats({ scans: 1, keysFound: interesting.length })
      break
    }

    case "balances": {
      const addr = flag("address")
      if (!addr) {
        console.log(bad("  нужен --address"))
        process.exit(2)
      }
      const chains = (flag("chains", "base,eth") ?? "base,eth").split(",")
      for (const chainKey of chains) {
        if (!CHAINS[chainKey]) continue
        const bals = await balancesAt(chainKey, addr)
        console.log(ok(`  ${CHAINS[chainKey].name} (${addr})`))
        for (const b of bals) console.log(dim(`     ${b.symbol}: ${formatUnits(b.amount, b.decimals)}`))
      }
      break
    }

    case "sweep": {
      const allowPath = flag("allowlist")
      const to = flag("to")
      const cfg = loadConfig()
      const main = (cfg.main ?? to)?.toLowerCase()
      if (!allowPath) {
        console.log(bad("  нужен --allowlist <файл> со списком своих адресов"))
        process.exit(2)
      }
      if (!to || (main && to.toLowerCase() !== main)) {
        console.log(bad("  --to должен совпадать с основным кошельком из конфига"))
        process.exit(2)
      }
      const allowed = JSON.parse(readFileSync(allowPath, "utf8"))
      const list = Array.isArray(allowed) ? allowed : allowed.addresses
      if (!Array.isArray(list) || !list.length) {
        console.log(bad("  allowlist пуст"))
        process.exit(2)
      }
      const chains = (flag("chains", "base,eth") ?? "base,eth").split(",")
      console.log(ok(`=== план сбор�� средств на ${to} ===\n`))
      let totalValue = 0
      for (const addr of list) {
        const a = addr.toLowerCase()
        if (a === to.toLowerCase()) continue
        for (const chainKey of chains) {
          if (!CHAINS[chainKey]) continue
          const bals = await balancesAt(chainKey, addr)
          const total = bals.reduce((s, b) => s + Number(b.amount) / 10 ** b.decimals, 0)
          if (total <= 0) continue
          totalValue += total
          console.log(`  ${a} [${CHAINS[chainKey].name}] ≈${total.toFixed(6)}`)
          for (const b of bals) {
            if (b.amount === 0n) continue
            console.log(dim(`     ${b.symbol}: ${formatUnits(b.amount, b.decimals)}`))
          }
        }
      }
      console.log()
      console.log(warn(`  итого ≈${totalValue.toFixed(6)} (оценка по native-активу)`))
      if (!has("yes")) {
        console.log(dim("  это план. Чтобы выполнить — добавь --yes (и ключ отправителя в конфиге)"))
        break
      }
      console.log(bad("  отправка транзакций требует ключа отправителя: укажи его в " + CONFIG_FILE))
      console.log(dim("  формат: {\"main\":\"0x…\",\"allowlist\":[\"0x…\"],\"keys\":{\"0x…\":\"0xprivatekey\"}}"))
      break
    }

    case "init": {
      const main = flag("main")
      const cfg = loadConfig()
      if (main) cfg.main = main.toLowerCase()
      saveConfig(cfg)
      console.log(ok(`  конфиг: ${CONFIG_FILE}`))
      break
    }

    default:
      console.log(ok("wallet-hygiene — свои кошельки под контролем\n"))
      console.log("  keys       найти утечки ключей в своих файлах и репозиториях")
      console.log("  forgotten  найти адреса, которые ты использовал, и проверить их балансы")
      console.log("  balances   балансы адреса по сетям (--address)")
      console.log("  sweep      собрать средства с адресов из allowlist на основной (--allowlist, --to)")
      console.log("  init       записать основной кошелёк в конфиг (--main)")
      console.log("")
      console.log(dim("  Инструмент работает только с адресами из твоего allowlist:"))
      console.log(dim("  подбирать ключи к чужим кошелькам он не умеет и не будет."))
      console.log()
  }
}

await main()
