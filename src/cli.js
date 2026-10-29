import { formatUnits } from "viem"
import { isAddress } from "./address.js"
import { createApiServer, listen } from "./api.js"
import { balancesAt, createChainClient } from "./balances.js"
import { CHAINS } from "./chains.js"
import { loadConfig, loadKeyMap, readAllowlist, saveConfig } from "./config.js"
import { SecretEgressError, redact, sealEnvironmentSecrets } from "./privacy.js"
import { findKeyLeaks, findOwnAddresses, isTrackedByGit } from "./scan.js"
import { sweepOne } from "./sweep.js"
import { paymentConfig } from "./x402.js"

const ok = (s) => `\x1b[32m${s}\x1b[0m`
const bad = (s) => `\x1b[31m${s}\x1b[0m`
const warn = (s) => `\x1b[33m${s}\x1b[0m`
const dim = (s) => `\x1b[2m${s}\x1b[0m`

function flag(argv, name, def = null) {
  const i = argv.indexOf(`--${name}`)
  return i >= 0 ? argv[i + 1] : def
}

function has(argv, name) {
  return argv.includes(`--${name}`)
}

function rootsFrom(argv, env) {
  const roots = []
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--root" && argv[i + 1]) roots.push(argv[++i])
  }
  if (roots.length) return roots
  if (env.WALLET_HYGIENE_ROOTS) {
    return env.WALLET_HYGIENE_ROOTS.split(",").map((s) => s.trim()).filter(Boolean)
  }
  return [process.cwd()]
}

function chainsFrom(argv) {
  return (flag(argv, "chains", "base,eth") ?? "base,eth").split(",").map((s) => s.trim()).filter(Boolean)
}

function unknownChains(chains) {
  return chains.filter((c) => !CHAINS[c])
}

function severityOf(file) {
  if (/[\\/](lib|node_modules|vendor|testdata|fixtures)[\\/]/i.test(file)) return "info"
  if (file.endsWith("(git history)")) return "critical"
  if (isTrackedByGit(file)) return "critical"
  if (/[\\/](secrets|\.config)[\\/]/.test(file) || file.endsWith("/.env") || file.endsWith("\\.env")) return "info"
  return "medium"
}

function printHelp(log) {
  log(ok("wallet-hygiene — свои кошельки под контролем\n"))
  log("  keys       найти утечки ключей в своих файлах и репозиториях")
  log("  forgotten  найти адреса, которые ты использовал, и проверить их балансы")
  log("  balances   балансы адреса по сетям (--address)")
  log("  sweep      собрать средства с адресов из allowlist на основной (--allowlist, --to)")
  log("  init       записать основной кошелёк в конфиг (--main)")
  log("  serve      HTTP API балансов; оплата x402 включается переменными окружения")
  log("")
  log(dim("  Инструмент работает только с адресами из твоего allowlist:"))
  log(dim("  подбирать ключи к чужим кошелькам он не умеет и не будет."))
  log(dim("  Приватные ключи и seed-фразы никуда не отправляются. См. docs/SECURITY.md"))
  log()
}

export async function run(argv, deps = {}) {
  const env = deps.env ?? process.env
  const log = deps.log ?? console.log
  const err = deps.err ?? console.error
  const cmd = argv[0] ?? "help"
  try {
    sealEnvironmentSecrets(env)
  } catch (e) {
    err(bad(redact(e.message)))
    return 1
  }

  try {
    if (cmd === "help" || cmd === "--help" || cmd === "-h") {
      printHelp(log)
      return 0
    }
    if (cmd === "keys") return await commandKeys(argv, env, log, deps)
    if (cmd === "forgotten") return await commandForgotten(argv, env, log, err, deps)
    if (cmd === "balances") return await commandBalances(argv, log, err, deps)
    if (cmd === "sweep") return await commandSweep(argv, env, log, err, deps)
    if (cmd === "init") return commandInit(argv, env, log, err)
    if (cmd === "serve") return await commandServe(argv, env, log, err, deps)
    printHelp(log)
    return 2
  } catch (e) {
    if (e instanceof SecretEgressError) {
      err(bad("отказ: инструмент не отправляет приватные ключи и секреты в сеть"))
      return 1
    }
    err(bad(redact(e.message || String(e))))
    return 1
  }
}

async function commandKeys(argv, env, log, deps) {
  log(ok("=== поиск утечек ключей в твоих файлах ===\n"))
  const find = deps.findKeyLeaks ?? findKeyLeaks
  const findings = find(rootsFrom(argv, env), { git: !has(argv, "no-git") })
  if (!findings.length) {
    log(ok("  утечек не найдено"))
    return 0
  }
  const classified = findings.map((f) => ({ ...f, severity: f.vendor ? "info" : severityOf(f.file) }))
  const order = { critical: 0, medium: 1, info: 2 }
  classified.sort((a, b) => order[a.severity] - order[b.severity])
  for (const f of classified) {
    const label = f.severity === "critical" ? bad : f.severity === "medium" ? warn : dim
    const gitNote = f.severity === "critical" ? " — ФАЙЛ В GIT" : ""
    log(label(`  [${f.severity}] ${f.id}: ${f.why}${gitNote}`))
    log(dim(`     ${f.file}`))
    log(dim(`     ${f.sample}`))
  }
  const crit = classified.filter((f) => f.severity === "critical").length
  const med = classified.filter((f) => f.severity === "medium").length
  log()
  if (crit) log(bad(`  критично: ${crit} — ключ в git считается скомпрометированным, смени его`))
  if (med) log(warn(`  стоит проверить: ${med}`))
  log(dim(`  в ожидаемых местах (secrets/, .env, вендор): ${classified.length - crit - med}`))
  return crit ? 1 : 0
}

async function commandForgotten(argv, env, log, err, deps) {
  log(ok("=== забытые адреса: где ты их оставлял ===\n"))
  const chains = chainsFrom(argv)
  const badChains = unknownChains(chains)
  if (badChains.length) {
    err(bad(`  неизвестная сеть: ${badChains.join(", ")}`))
    return 2
  }
  const roots = rootsFrom(argv, env)
  const gitDirs = has(argv, "no-git") ? [] : roots
  const found = (deps.findOwnAddresses ?? findOwnAddresses)(roots, gitDirs)
  const main = loadConfig(env).main
  const lookup = deps.balancesAt ?? balancesAt
  let hits = 0
  for (const { address, sources } of found) {
    if (main && address === main) continue
    for (const chainKey of chains) {
      let bals
      try {
        bals = await lookup(chainKey, address, [], { fetchFn: deps.fetchFn, env, client: deps.clientFor?.(chainKey) })
      } catch (e) {
        if (e instanceof SecretEgressError) throw e
        err(dim(`  ${address} [${chainKey}] rpc: ${redact(e.message)}`))
        continue
      }
      const total = bals.reduce((sum, b) => sum + Number(b.amount) / 10 ** b.decimals, 0)
      if (total <= 0) continue
      hits += 1
      log(warn(`  ${address}  [${CHAINS[chainKey].name}]  ≈${total.toFixed(6)}`))
      for (const b of bals) {
        if (b.amount === 0n) continue
        log(dim(`     ${b.symbol}: ${formatUnits(b.amount, b.decimals)}`))
      }
      log(dim(`     где: ${sources.join(", ")}`))
      break
    }
  }
  if (!hits) log(ok("  адресов с остатками не найдено"))
  else log(dim("\n  добавь адрес в allowlist и запусти sweep — газ платит сам кошелёк"))
  return 0
}

async function commandBalances(argv, log, err, deps) {
  const addr = flag(argv, "address")
  if (!addr || !isAddress(addr)) {
    err(bad("  нужен --address 0x… (20 байт)"))
    return 2
  }
  const chains = chainsFrom(argv)
  const badChains = unknownChains(chains)
  if (badChains.length) {
    err(bad(`  неизвестная сеть: ${badChains.join(", ")}`))
    return 2
  }
  const lookup = deps.balancesAt ?? balancesAt
  for (const chainKey of chains) {
    const bals = await lookup(chainKey, addr, [], { fetchFn: deps.fetchFn, client: deps.clientFor?.(chainKey) })
    log(ok(`  ${CHAINS[chainKey].name} (${addr})`))
    for (const b of bals) log(dim(`     ${b.symbol}: ${formatUnits(b.amount, b.decimals)}`))
  }
  return 0
}

async function commandSweep(argv, env, log, err, deps) {
  const allowPath = flag(argv, "allowlist")
  const to = flag(argv, "to")
  const cfg = loadConfig(env)
  if (cfg.keysIgnored) {
    err(warn("  в config.json есть поле keys — оно игнорируется и никуда не отправляется"))
  }
  if (!allowPath) {
    err(bad("  нужен --allowlist <файл> со списком своих адресов"))
    return 2
  }
  if (!to || !isAddress(to)) {
    err(bad("  нужен --to 0x… — основной кошелёк"))
    return 2
  }
  if (cfg.main && to.toLowerCase() !== cfg.main) {
    err(bad("  --to должен совпадать с основным кошельком из конфига"))
    return 2
  }
  const execute = has(argv, "yes")
  if (execute && !cfg.main) {
    err(bad("  для --yes сначала выполни init --main 0x… и используй тот же --to"))
    return 2
  }
  const chains = chainsFrom(argv)
  const badChains = unknownChains(chains)
  if (badChains.length) {
    err(bad(`  неизвестная сеть: ${badChains.join(", ")}`))
    return 2
  }
  const list = readAllowlist(allowPath)
  const keys = execute ? loadKeyMap(env) : null
  log(ok(`=== план сбора средств на ${to} ===\n`))
  let planned = 0n
  for (const addr of list) {
    if (addr === to.toLowerCase()) continue
    for (const chainKey of chains) {
      const client = deps.clientFor
        ? deps.clientFor(chainKey, addr)
        : createChainClient(chainKey, { env, fetchFn: deps.fetchFn })
      let result
      try {
        result = await (deps.sweepOne ?? sweepOne)({
          chainKey,
          from: addr,
          to,
          execute,
          privateKey: execute ? keys.get(addr) ?? null : null,
          client,
        })
      } catch (e) {
        if (e.code === "NO_KEY") {
          err(bad(`  нет локального ключа для ${addr}. Укажи WALLET_HYGIENE_KEYFILE (режим 0600) или WALLET_HYGIENE_KEYS. Ключ остаётся на этой машине.`))
          return 2
        }
        throw e
      }
      if (result.skip || result.value === 0n) continue
      planned += result.value
      log(`  ${addr} [${CHAINS[chainKey].name}] ${formatUnits(result.value, 18)} ETH`)
      log(dim(`     резерв на газ: ${formatUnits(result.reserve, 18)} ETH`))
      if (result.hash) log(ok(`     tx ${result.hash}`))
    }
  }
  log()
  if (planned === 0n) log(ok("  переводить нечего"))
  else if (!execute) log(dim("  это план. Чтобы подписать и отправить — добавь --yes. Ключ остаётся на этой машине."))
  else log(warn("  отправка закончена. Приватный ключ в сеть не передавался."))
  return 0
}

function commandInit(argv, env, log, err) {
  const main = flag(argv, "main")
  if (main && !isAddress(main)) {
    err(bad("  --main должен быть адресом 0x и 20 байт"))
    return 2
  }
  const file = saveConfig(main ? { main } : {}, env)
  const cfg = loadConfig(env)
  log(ok(`  конфиг: ${file}`))
  if (!cfg.main) log(dim("  основной кошелёк не задан — повтори с --main 0x…"))
  log(dim("  ключи в этот файл не записываются"))
  return 0
}

async function commandServe(argv, env, log, err, deps) {
  const config = paymentConfig(env)
  const server = (deps.createApiServer ?? createApiServer)({
    env,
    fetchFn: deps.fetchFn,
    lookup: deps.lookup,
  })
  const addr = await listen(server, { host: flag(argv, "host"), port: flag(argv, "port") }, env)
  log(ok(`  слушает http://${addr.host}:${addr.port}`))
  log(dim(config.enabled
    ? `  x402 включён: ${config.amount} atomic → ${config.payTo} (${config.network})`
    : "  x402 выключен. Чтобы брать оплату: X402_ENABLED=true и X402_PAY_TO=0x…"))
  if (deps.serveHold === false) {
    await new Promise((resolve) => server.close(resolve))
    return 0
  }
  await new Promise(() => {})
  return 0
}
