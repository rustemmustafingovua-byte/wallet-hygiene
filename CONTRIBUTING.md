# Contributing

Thanks for your interest in contributing!

## Development

```bash
git clone https://github.com/rustemmustafingovua-byte/wallet-hygiene.git
cd wallet-hygiene
npm install
npm test
```

## Guidelines

- Follow the existing code style.
- Add tests for new behavior.
- Do not add a network call that can carry a private key, seed, or access token. Outbound calls go through `createGuardedFetch`. `npm test` checks this.
- Open an issue before large changes.

MIT © rustemmustafingovua-byte
