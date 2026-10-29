# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.2.0]

### Added
- Local native sweep: sign on this machine, broadcast only the signed transaction, destination must match `init --main`.
- HTTP API (`serve`) for public balance lookups. x402 v2 charges after a free quota when `X402_ENABLED` and `X402_PAY_TO` are set.
- Egress guard so registered private keys, seed phrases, and access tokens cannot be sent.
- npm publish workflow and a Docker image for the API.

### Changed
- Scans default to the current directory (`--root` or `WALLET_HYGIENE_ROOTS`), not a hardcoded home path.
- Balance reads use the chain you asked for.
- Keys are not read from `config.json`. A world-readable key file is refused.
- CI installs with `npm ci` on Node 20, 22, and 24.

### Removed
- Dashboard webhook. Scan results are not uploaded.

## [0.1.0]

### Added
- Initial public release.
