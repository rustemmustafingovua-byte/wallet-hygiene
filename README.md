<div align="center">

# Wallet Hygiene

[![CI](https://github.com/rustemmustafingovua-byte/wallet-hygiene/actions/workflows/ci.yml/badge.svg)](https://github.com/rustemmustafingovua-byte/wallet-hygiene/actions/workflows/ci.yml) [![npm](https://img.shields.io/npm/v/wallet-hygiene?color=cb3837&logo=npm)](https://www.npmjs.com/package/wallet-hygiene) [![license](https://img.shields.io/badge/license-MIT-8b949e?logo=opensourceinitiative)](./LICENSE)

</div>

---

**Keep your own wallets under control: find leaked keys, find forgotten addresses with leftover funds, and sweep them to your main wallet.**

---

⭐ **Star us on GitHub** if this project helps you build better agents!

---

## 🚀 Быстрый старт

```bash
git clone https://github.com/rustemmustafingovua-byte/wallet-hygiene
cd wallet-hygiene && npm install
npm test
```

---

## 🎯 Демо

```bash
wallet-hygiene init --main 0xYourMainWallet
wallet-hygiene keys
wallet-hygiene forgotten --chains base,eth
wallet-hygiene sweep --allowlist allowlist.json --to 0xYourMainWallet --yes
```

---

## 💰 Монетизация

- **Security audits**: аудит безопасности кошельков для фондов и enterprise
- **Consulting**: настройка процессов ключ-гигиены для команды
- **Custom chain support**: добавление новых сетей под заказ
- **SaaS hosting**: хостинг сервиса с white-label для крипто-компаний

---

## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/amazing-thing`)
3. Commit your changes (`git commit -m 'feat: add amazing thing'`)
4. Push to the branch (`git push origin feat/amazing-thing`)
5. Open a Pull Request

Bug reports and feature requests are welcome on the [Issues](https://github.com/rustemmustafingovua-byte/wallet-hygiene/issues) page.

MIT © rustemmustafingovua-byte
