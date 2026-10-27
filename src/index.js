/**
 * wallet-hygiene — публичный API пакета.
 *
 * Инструмент работает только с адресами, которые ты сам перечислил в allowlist:
 * он находит твои забытые кошельки с остатками, утечки ключей и помогает
 * собрать средства на основной кошелёк. Подбирать ключи к чужим кошелькам
 * он не умеет — это кража, а не гигиена.
 */
export {
  findKeyLeaks,
  findOwnAddresses,
  walk,
  balancesAt,
  CHAINS,
  isKnownConstant,
  KNOWN_TOKEN_ADDRESSES,
} from "../bin/wallet-hygiene.js"
