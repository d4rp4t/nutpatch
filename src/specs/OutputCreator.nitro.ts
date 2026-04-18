import { type HybridObject, type UInt64 } from 'react-native-nitro-modules'

//seems like nitrogen cannot process external imports.

/**
 * replaces cashu-ts `SerializedBlindedMessage`
 * B_ is a hex-encoded compressed secp256k1 point
 */
export interface NativeBlindedMessage {
  amount: UInt64
  B_: string
  id: string
}

/**
 * native representation of cashu-ts `OutputData`
 * bigint blindingFactor and Uint8Array secret are encoded as hex strings.
 */
export interface NativeOutputData {
  blindedMessage: NativeBlindedMessage
  /** Hex-encoded 32-byte scalar (mirrors blindingFactor bigint) */
  blindingFactor: string
  /** Hex-encoded secret bytes */
  secret: string
  /**
   * Hex-encoded compressed ephemeral pubkey E = e*G when P2BK blinding
   * was applied, empty string otherwise.
   */
  ephemeralE: string
}

/**
 * Mirrors cashu-ts `HasKeysetKeys`.
 * keys maps amount (as decimal string) to the mint's hex-encoded compressed pubkey.
 */
export interface Keyset {
  id: string
  keys: Record<string, string>
}

/**
 * Simplified P2PK spending condition options.
 * pubkeys is always an array (cashu-ts allows string | string[]).
 */
export interface NitroP2PKOptions {
  pubkeys: string[]
  locktime?: number
  refundKeys?: string[]
  requiredSignatures?: number
  requiredRefundSignatures?: number
  /** P2PKTag[] — each tag is [key, ...values] flattened as string[] */
  additionalTags?: string[][]
  blindKeys?: boolean
  /** 'SIG_INPUTS' | 'SIG_ALL' */
  sigFlag?: string
  hashlock?: string
}

// ---------------------------------------------------------------------------
// HybridObject spec
// ---------------------------------------------------------------------------

export interface OutputCreator extends HybridObject<{
  ios: 'c++'
  android: 'c++'
}> {
  createP2PKData(
    p2pk: NitroP2PKOptions,
    amount: UInt64,
    keyset: Keyset,
    customSplit?: UInt64[]
  ): NativeOutputData[]

  createSingleP2PKData(
    p2pk: NitroP2PKOptions,
    amount: UInt64,
    keysetId: string
  ): NativeOutputData

  createRandomData(
    amount: UInt64,
    keyset: Keyset,
    customSplit?: UInt64[]
  ): NativeOutputData[]

  createSingleRandomData(amount: UInt64, keysetId: string): NativeOutputData

  createDeterministicData(
    amount: UInt64,
    seed: ArrayBuffer,
    counter: UInt64,
    keyset: Keyset,
    customSplit?: UInt64[]
  ): NativeOutputData[]

  createSingleDeterministicData(
    amount: UInt64,
    seed: ArrayBuffer,
    counter: UInt64,
    keysetId: string
  ): NativeOutputData
}
