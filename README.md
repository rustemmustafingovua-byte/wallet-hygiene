<div align="center">

# Wallet Hygiene

[![CI](https://github.com/rustemmustafingovua-byte/wallet-hygiene/actions/workflows/ci.yml/badge.svg)](https://github.com/rustemmustafingovua-byte/wallet-hygiene/actions/workflows/ci.yml) [![npm](https://img.shields.io/npm/v/wallet-hygiene?color=cb3837&logo=npm)](https://www.npmjs.com/package/wallet-hygiene) [![license](https://img.shields.io/badge/license-MIT-8b949e?logo=opensourceinitiative)](./LICENSE)

**Find leaked keys and forgotten balances on your own machine. Sweep them to your main wallet. Private keys are never uploaded.**

</div>

The CLI scans directories you point it at, checks balances of addresses it found there, and can move the native balance to a main address you saved. The optional HTTP API sells the same public balance lookup to other people via [x402](https://www.x402.org). It does not accept keys.

Details of what is sent over the network: [docs/SECURITY.md](docs/SECURITY.md).

## Install

Requires Node.js 20 or newer.

```bash
npm install -g wallet-hygiene
```

From a checkout:

```bash
npm ci
npm test
node bin/wallet-hygiene.js --help
```

## Commands

```bash
wallet-hygiene init --main 0xYourMainWallet
wallet-hygiene keys --root .
wallet-hygiene forgotten --root . --chains base,eth
wallet-hygiene balances --address 0xYourAddress --chains base,eth
wallet-hygiene sweep --allowlist allowlist.json --to 0xYourMainWallet --chains base
wallet-hygiene sweep --allowlist allowlist.json --to 0xYourMainWallet --chains base --yes
wallet-hygiene serve
```

`sweep` prints a plan. `--yes` signs locally and broadcasts the signed transaction. The source address must be in the allowlist, and `--to` must match the address saved by `init`. Gas is paid by the source wallet; a fee reserve is left behind so the transfer can still be mined.

Allowlist file:

```json
["0xabc...", "0xdef..."]
```

Put keys in a separate file, mode `0600`:

```bash
install -m 600 /dev/null "$HOME/.config/wallet-hygiene/keys.json"
# {"0xSourceAddress":"0x...64 hex chars..."}
export WALLET_HYGIENE_KEYFILE="$HOME/.config/wallet-hygiene/keys.json"
```

`WALLET_HYGIENE_KEYS` (a JSON object) overrides the file for the same address. Prefer the file. Do not commit either.

Public Anvil/Hardhat keys are ignored. Token contracts in the built-in list are not reported as forgotten wallets.

## Configuration

Copy `.env.example`. Anything secret stays out of git.

| Variable | Purpose |
| --- | --- |
| `WALLET_HYGIENE_CONFIG_DIR` | Where `config.json` is written. Default `~/.config/wallet-hygiene`. |
| `WALLET_HYGIENE_MAIN` | Main address if `init` has not been run. |
| `WALLET_HYGIENE_ROOTS` | Comma-separated scan roots. Default is the current directory. `--root` overrides this. |
| `WALLET_HYGIENE_KEYFILE` | JSON map of address to private key. Must be mode `0600`. |
| `WALLET_HYGIENE_KEYS` | Same map in the environment. Do not set this on the public API. |
| `WALLET_HYGIENE_RPC_BASE` / `_ETH` / `_ARBITRUM` / `_OPTIMISM` / `_POLYGON` | RPC URL for that chain. |
| `HOST`, `PORT` | API bind address. Default `127.0.0.1:8787`. The container sets `HOST=0.0.0.0`. |
| `X402_ENABLED` | `true` to charge. Anything else leaves the API free. |
| `X402_PAY_TO` | Your receiving address. Required when charging. |
| `X402_NETWORK` | CAIP-2 network. Default `eip155:8453` (Base). |
| `X402_ASSET` | Token address. Default Base USDC. |
| `X402_PRICE_ATOMIC` | Price in token base units. Default `10000` (0.01 USDC). |
| `X402_FACILITATOR_URL` | Default `https://x402.org/facilitator`. |
| `X402_FACILITATOR_AUTH` | Optional facilitator credential. Refused if it looks like a wallet key. |
| `X402_FREE_QUOTA` | Free balance calls per client per day before HTTP 402. Default `10`. |
| `X402_MAX_ADDRESSES` | Addresses per paid call. Default `20`, capped at `100`. |

## Paid API

`GET /health` and `GET /v1/pricing` are always free.

`GET /v1/balances?address=0x…&chains=base,eth` and `POST /v1/balances` with `{"addresses":["0x…"],"chains":["base"]}` return public balances. With payments off, every call is free and the body says `"payments":"disabled"`. With payments on, the first `X402_FREE_QUOTA` calls per day are free; the next call is HTTP 402 with a base64 `PAYMENT-REQUIRED` header (x402 v2, scheme `exact`). A client retries with `PAYMENT-SIGNATURE`. This server checks that the payment matches your price and address, asks the facilitator to verify, runs the lookup, then asks the facilitator to settle. The balance report is returned only after settle succeeds, with a `PAYMENT-RESPONSE` header.

The API rejects bodies that contain a private key, seed phrase, or access token, and it does not scan files.

```bash
npm start
curl -s localhost:8787/health
curl -s "localhost:8787/v1/balances?address=0x0000000000000000000000000000000000000000&chains=base"
```

## Start earning

Nothing here moves funds or deploys. You do the last mile:

1. Pick the address that should receive USDC. This is `X402_PAY_TO`. It is not a private key.
2. Rehearse on Base Sepolia before mainnet: `X402_ENABLED=true`, `X402_NETWORK=eip155:84532`, `X402_ASSET=0x036CbD53842c5426634e7929541eC2318f3dCF7e` (Sepolia USDC), `X402_PAY_TO` set to your test address, `X402_FACILITATOR_URL=https://x402.org/facilitator`. `curl -i` a balance URL until you see `402` and `PAYMENT-REQUIRED`. Pay it with an x402 client (for example `@x402/fetch`). Confirm the USDC landed in `X402_PAY_TO`.
3. Switch to mainnet: `X402_NETWORK=eip155:8453`, `X402_ASSET=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, price `X402_PRICE_ATOMIC=10000` (0.01 USDC) or whatever you want to charge. Restart the process.
4. Run it: `docker build -t wallet-hygiene .` then `docker run --rm -p 8787:8787 --env-file .env wallet-hygiene`. Put a real host in front of it. Do not put `WALLET_HYGIENE_KEYS` in that environment.
5. Publish the CLI when you are ready. Add a repository secret `NPM_TOKEN` (npm automation token, publish rights). Tag `v0.2.0`. The Release workflow creates the GitHub release; **Publish to npm** runs on that release. The name `wallet-hygiene` was free on the npm registry on 2026-10-29 — check again just before you tag. GitHub Packages still publishes on a `pkg-v*` tag.
6. GitHub Sponsors is already listed in `.github/FUNDING.yml`. Turn the sponsor button on for `rustemmustafingovua-byte` if you want that path too.

Free quota is counted in process memory. One container is enough to start. Add a shared store before you run more than one instance.

## Development

```bash
npm ci
npm test
npm run lint
```

CI runs that on Node 20, 22, and 24, and builds the Docker image. It does not publish and it does not broadcast transactions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT © rustemmustafingovua-byte

## Кратко

Ключи и seed ищутся только на твоей машине и никуда не отправляются. `sweep` без `--yes` ничего не подписывает. Платный API включается так: `X402_ENABLED=true` и `X402_PAY_TO` — твой адрес для USDC. Сначала Base Sepolia, потом Base mainnet. Образ: `docker build` и `docker run --env-file .env`. В npm — секрет `NPM_TOKEN` и тег `v0.2.0`. Не клади файл ключей в образ и не запускай `sweep --yes` на чужих адресах: allowlist и `init --main` это не пропустят.
