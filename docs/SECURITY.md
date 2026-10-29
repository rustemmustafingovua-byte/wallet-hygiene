# Security

wallet-hygiene looks for leaked keys and leftover balances on **your** machine, and it can sweep those balances to a main wallet you already saved. It does not guess keys, it does not scan addresses you did not supply, and it does not upload what it finds.

## What never leaves the machine

These values are not put in an HTTP body, URL, header, or log line:

- private keys (`0x` + 32 bytes) loaded from `WALLET_HYGIENE_KEYFILE` or `WALLET_HYGIENE_KEYS`
- seed phrases found next to words like `seed` or `mnemonic`
- access tokens found in your files (`ghp_`, `gho_`, `github_pat_`, `npm_`)
- the raw text of a finding (the CLI prints a short redacted sample only)

Every outbound call goes through `createGuardedFetch` in `src/privacy.js`. If a request would contain a secret this process has seen, it throws `SecretEgressError` and the request is not sent.

There is no telemetry webhook. A previous `DASHBOARD_WEBHOOK_URL` path was removed. `test/privacy.test.js` fails the build if that path, or a direct `fetch(` outside the guard, comes back.

## What is sent, and why

| Call | When | Payload |
| --- | --- | --- |
| JSON-RPC to the chain RPC (`WALLET_HYGIENE_RPC_*` or the public default) | `balances`, `forgotten`, `sweep`, and `GET/POST /v1/balances` | Method name and the **public address**. A sweep also sends the **signed transaction**, not the key. |
| `POST {X402_FACILITATOR_URL}/verify` and `/settle` | A client pays for `/v1/balances` after the free quota | Only the x402 exact-scheme fields (authorization, 65-byte signature, and the price we advertised). Extra fields are dropped. `X402_FACILITATOR_AUTH` is sent only if you set it. |

`X402_FACILITATOR_AUTH` is an operator credential for the facilitator. It is sent only to the facilitator URL. The process refuses to start if that value looks like a wallet private key.

Public RPCs learn which addresses you asked about. Use your own RPC URL when that matters. They do not receive keys.

## Keys on disk

- `~/.config/wallet-hygiene/config.json` (or `WALLET_HYGIENE_CONFIG_DIR`) stores `main` and `allowlist` only, mode `0600`.
- If that file already contains a `keys` field, it is ignored and the file is not rewritten, so the only copy is not deleted automatically. Move the keys yourself, then delete the field.
- Sweep reads keys from `WALLET_HYGIENE_KEYFILE` (must be mode `0600`) or `WALLET_HYGIENE_KEYS`. The environment variable overrides the file for the same address.
- `--yes` signs with viem on this machine and broadcasts the signed transaction. The destination must match `init --main`. Without `--yes`, sweep only prints a plan.
- The HTTP API does not read key files and rejects any body or query that contains a private key, a token, or a seed phrase. It does not scan your disk.

## How to verify

```bash
npm test
```

The tests that lock this in:

- `test/privacy.test.js` — no webhook in source, balance RPC hits the selected chain, a loaded key is absent from the request, a key-shaped facilitator token is refused
- `test/sweep.test.js` — the signed transaction and the CLI log do not contain the private key; the guard still blocks a body that does
- `test/api.test.js` — a posted private key returns 400 and is not echoed or forwarded; a paid call's facilitator body does not contain `WALLET_HYGIENE_KEYS`
- `test/hygiene.test.js` — findings store a redacted sample, not the secret

## Limits

The guard stops secrets this process has registered, plus secret-shaped fields (`privateKey`, `mnemonic`, …), bearer tokens, and seed phrases. It does not treat every 32-byte hex string as a key, because an x402 nonce is also 32 bytes. A signed transaction is allowed only when it does not contain a registered key.

Sweeping sends the signed transaction to the RPC. That is required to move funds. The private key is not part of that transaction.

Free-quota state for the paid API is in memory on one process. Run one instance, or put a store in front, before you rely on the quota.
