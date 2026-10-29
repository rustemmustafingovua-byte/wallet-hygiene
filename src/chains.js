import { arbitrum, base, mainnet, optimism, polygon } from "viem/chains"

export const CHAINS = {
  base: {
    name: "Base",
    id: 8453,
    rpc: "https://mainnet.base.org",
    rpcEnv: "WALLET_HYGIENE_RPC_BASE",
    chain: base,
  },
  eth: {
    name: "Ethereum",
    id: 1,
    rpc: "https://ethereum-rpc.publicnode.com",
    rpcEnv: "WALLET_HYGIENE_RPC_ETH",
    chain: mainnet,
  },
  arbitrum: {
    name: "Arbitrum",
    id: 42161,
    rpc: "https://arb1.arbitrum.io/rpc",
    rpcEnv: "WALLET_HYGIENE_RPC_ARBITRUM",
    chain: arbitrum,
  },
  optimism: {
    name: "Optimism",
    id: 10,
    rpc: "https://mainnet.optimism.io",
    rpcEnv: "WALLET_HYGIENE_RPC_OPTIMISM",
    chain: optimism,
  },
  polygon: {
    name: "Polygon",
    id: 137,
    rpc: "https://polygon-rpc.com",
    rpcEnv: "WALLET_HYGIENE_RPC_POLYGON",
    chain: polygon,
  },
}

export function chainRpc(chainKey, env = process.env) {
  const chain = CHAINS[chainKey]
  if (!chain) return null
  const override = env[chain.rpcEnv]
  return override && override.trim() ? override.trim() : chain.rpc
}
