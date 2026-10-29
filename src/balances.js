import { createPublicClient, erc20Abi, http } from "viem"
import { isAddress } from "./address.js"
import { CHAINS, chainRpc } from "./chains.js"
import { createGuardedFetch } from "./privacy.js"

export function createChainClient(chainKey, { fetchFn, env = process.env } = {}) {
  const meta = CHAINS[chainKey]
  if (!meta) throw new Error(`unknown chain: ${chainKey}`)
  const rpc = chainRpc(chainKey, env)
  return createPublicClient({
    chain: meta.chain,
    transport: http(rpc, { fetchFn: createGuardedFetch(fetchFn ?? globalThis.fetch) }),
  })
}

/** Native balance plus optional ERC-20 balances. Amounts are bigints. */
export async function balancesAt(chainKey, address, tokens = [], options = {}) {
  if (!CHAINS[chainKey]) throw new Error(`unknown chain: ${chainKey}`)
  if (!isAddress(address)) throw new Error("invalid address")
  const client = options.client ?? createChainClient(chainKey, options)
  const native = await client.getBalance({ address })
  const out = [{ symbol: "ETH", decimals: 18, amount: native }]
  for (const t of tokens) {
    if (!isAddress(t.address)) continue
    try {
      const amount = await client.readContract({
        address: t.address,
        abi: erc20Abi,
        functionName: "balanceOf",
        args: [address],
      })
      out.push({ symbol: t.symbol, decimals: t.decimals ?? 18, amount })
    } catch {
      // the contract did not answer; skip it
    }
  }
  return out
}
