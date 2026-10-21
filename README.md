<div align="center">

# wallet-hygiene

**Keep your own wallets under control: find leaked keys, find forgotten addresses with leftover funds, and sweep them to your main wallet.**

[![license](https://img.shields.io/badge/license-MIT-8b949e?logo=opensourceinitiative)](./LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D20-3c873a?logo=node.js)](https://nodejs.org)

</div>

---

## What it does

| Command | What it does |
|---|---|
| `keys` | finds private keys, seed phrases and access tokens in **your** files and repos; separates real leaks (in git) from expected storage (`secrets/`, `.env`) |
| `forgotten` | finds addresses you have used (git history, configs, logs) and checks their balances on every chain — your forgotten wallets |
| `balances` | native balance + token balances for an address, per chain |
| `sweep` | builds a plan to move funds from allow-listed addresses to your main wallet, then executes it (gas is paid by the source wallet, so no external funds are needed) |

## Install

```bash
npm i -g wallet-hygiene
```

## Use

```bash
wallet-hygiene init --main 0xYourMainWallet
wallet-hygiene keys
wallet-hygiene forgotten --chains base,eth
wallet-hygiene balances --address 0xYourOldWallet
wallet-hygiene sweep --allowlist allowlist.json --to 0xYourMainWallet
wallet-hygiene sweep --allowlist allowlist.json --to 0xYourMainWallet --yes
```

`allowlist.json`:

```json
{ "addresses": ["0xOldWalletOne", "0xOldWalletTwo"] }
```

## What it found in the wild

Running it on a real machine immediately surfaced something a normal wallet
balance view misses: **6.78 ETH sitting on `0xEeee…Eee` on Base** — the canonical
placeholder/burn address, invisible in every explorer UI you normally look at.
No key exists for it, so the money is stuck by design; the value of the report is
that you now *know* it is there instead of wondering where it went.

## The rules it follows

These are not limitations, they are the point:

- it touches **only** addresses from your allowlist;
- `--to` must match the main wallet from the config;
- `sweep` prints a plan first and needs `--yes` to move anything;
- the gas for a sweep is paid by the **source** wallet, so you need no funds anywhere else;
- it does not try to guess keys for wallets you do not own. That is theft, not hygiene.

## Chains

Base, Ethereum, Arbitrum, Optimism, Polygon. More via `CHAINS` in `bin/wallet-hygiene.js`.

## Tests

```bash
npm test     # 8 tests: detection precision, allowlist rules, tree walking
```

MIT © rustemmustafingovua-byte
