import { privateKeyToAccount } from "viem/accounts"
import { isAddress } from "./address.js"
import { CHAINS } from "./chains.js"
import { assertSafeOutbound, registerSecret } from "./privacy.js"

export const NATIVE_GAS = 21000n
/** L2s charge an extra data fee on top of the EVM gas price. Leave headroom. */
export const FEE_RESERVE_MULTIPLIER = 2n

export function planNativeSweep({ balance, maxFeePerGas, gasLimit = NATIVE_GAS } = {}) {
  if (typeof balance !== "bigint" || typeof maxFeePerGas !== "bigint") {
    throw new Error("balance and maxFeePerGas must be bigints")
  }
  if (balance < 0n || maxFeePerGas < 0n) throw new Error("negative amount")
  const reserve = gasLimit * maxFeePerGas * FEE_RESERVE_MULTIPLIER
  if (balance <= reserve) {
    return { value: 0n, reserve, skip: true, reason: "balance does not cover fee reserve" }
  }
  return { value: balance - reserve, reserve, skip: false, reason: null }
}

/**
 * Plan a native sweep and, when execute is set, sign it locally and broadcast
 * only the signed transaction. The private key is never placed in the client.
 */
export async function sweepOne({
  chainKey,
  from,
  to,
  execute = false,
  privateKey = null,
  client,
}) {
  if (!CHAINS[chainKey]) throw new Error(`unknown chain: ${chainKey}`)
  if (!isAddress(from) || !isAddress(to)) throw new Error("invalid address")
  if (!client) throw new Error("sweep client is required")

  const balance = await client.getBalance({ address: from })
  const fees = await client.estimateFeesPerGas()
  const maxFeePerGas = fees.maxFeePerGas ?? fees.gasPrice
  if (typeof maxFeePerGas !== "bigint") throw new Error("rpc did not return a fee")
  const priorityIn = fees.maxPriorityFeePerGas ?? 1n
  const maxPriorityFeePerGas = priorityIn > maxFeePerGas ? maxFeePerGas : priorityIn
  const plan = planNativeSweep({ balance, maxFeePerGas })
  const result = {
    ...plan,
    balance,
    maxFeePerGas,
    from: from.toLowerCase(),
    to: to.toLowerCase(),
    chainKey,
    hash: null,
  }
  if (!execute || plan.skip || from.toLowerCase() === to.toLowerCase()) return result
  if (!privateKey) {
    const err = new Error("missing local key")
    err.code = "NO_KEY"
    throw err
  }
  registerSecret(privateKey)
  const account = privateKeyToAccount(privateKey)
  if (account.address.toLowerCase() !== from.toLowerCase()) {
    throw new Error("local key does not match allowlisted address")
  }
  const nonce = await client.getTransactionCount({ address: from, blockTag: "pending" })
  const serialized = await account.signTransaction({
    type: "eip1559",
    chainId: CHAINS[chainKey].id,
    to,
    value: plan.value,
    gas: NATIVE_GAS,
    nonce,
    maxFeePerGas,
    maxPriorityFeePerGas,
  })
  assertSafeOutbound(serialized)
  result.hash = await client.sendRawTransaction({ serializedTransaction: serialized })
  return result
}
