import { NitroModules } from 'react-native-nitro-modules'
import {
  OutputData,
  type AmountLike,
  type HasKeysetKeys,
  type P2PKOptions,
  type P2PKTag,
  type SigFlag,
  Amount,
  deriveP2BKBlindedPubkeys,
} from '@cashu/cashu-ts'
import type { OutputCreator, Keyset, NitroP2PKOptions } from './specs/OutputCreator.nitro'
import type { OutputDataCreator } from './index'

const VALID_SIG_FLAGS = new Set<string>(['SIG_INPUTS', 'SIG_ALL'])

const RESERVED_P2PK_TAGS = new Set([
  'locktime',
  'pubkeys',
  'n_sigs',
  'refund',
  'n_sigs_refund',
  'sigflag',
])

function assertValidTagKey(key: string): void {
  if (!key || typeof key !== 'string') throw new Error('tag key must be a non empty string')
  if (RESERVED_P2PK_TAGS.has(key))
    throw new Error(`additionalTags must not use reserved key "${key}"`)
}

function normalizePubkey(pk: string): string {
  const hex = pk.toLowerCase()
  if (hex.length === 66 && (hex.startsWith('02') || hex.startsWith('03'))) return hex
  if (hex.length === 64) return `02${hex}`
  throw new Error(
    `Invalid pubkey, expected 33 byte compressed or 32 byte x only, got length ${hex.length}`
  )
}

function dedupeP2PKPubkeys(keys: string[]): string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const raw of keys) {
    const k = normalizePubkey(raw)
    const xOnly = k.slice(-64)
    if (!seen.has(xOnly)) {
      seen.add(xOnly)
      result.push(k)
    }
  }
  return result
}

function assertSigFlag(flag: string): void {
  if (!VALID_SIG_FLAGS.has(flag))
    throw new Error(`Invalid sigflag "${flag}": must be "SIG_INPUTS" or "SIG_ALL"`)
}

function assertPositiveInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 1)
    throw new Error(`${field} must be a positive integer, got ${value}`)
}

function assertSpendingConditionRules(
  mainKeyCount: number,
  refundKeyCount: number,
  nSigs: number | undefined,
  nSigsRefund: number | undefined,
  hasLocktime: boolean
): void {
  if (nSigs !== undefined) {
    assertPositiveInteger(nSigs, 'requiredSignatures (n_sigs)')
    if (nSigs > mainKeyCount)
      throw new Error(
        `requiredSignatures (n_sigs) (${nSigs}) exceeds available pubkeys (${mainKeyCount})`
      )
  }
  if (nSigsRefund !== undefined) {
    assertPositiveInteger(nSigsRefund, 'requiredRefundSignatures (n_sigs_refund)')
    if (refundKeyCount === 0)
      throw new Error('requiredRefundSignatures (n_sigs_refund) requires refund keys')
    if (nSigsRefund > refundKeyCount)
      throw new Error(
        `requiredRefundSignatures (n_sigs_refund) (${nSigsRefund}) exceeds available refund keys (${refundKeyCount})`
      )
  }
  if (refundKeyCount > 0 && !hasLocktime) throw new Error('refund keys require a locktime')
}

type NormalizedP2PK = {
  pubkeys: string[]
  refundKeys: string[]
  locktime?: number
  requiredSignatures?: number
  requiredRefundSignatures?: number
  additionalTags?: P2PKTag[]
  sigFlag?: SigFlag
  hashlock?: string
}

function normalizeP2PKOptions(p2pk: P2PKOptions): NormalizedP2PK {
  const pubkeys = dedupeP2PKPubkeys(Array.isArray(p2pk.pubkey) ? p2pk.pubkey : [p2pk.pubkey])
  const refundKeys = dedupeP2PKPubkeys(p2pk.refundKeys ?? [])
  if (pubkeys.length === 0) throw new Error('P2PK requires at least one pubkey')
  const totalKeys = pubkeys.length + refundKeys.length
  if (totalKeys > 10)
    throw new Error(`Too many pubkeys, ${totalKeys} provided, maximum allowed is 10 in total`)
  if (p2pk.sigFlag !== undefined) assertSigFlag(p2pk.sigFlag)

  const requiredSignatures = p2pk.requiredSignatures ?? 1
  const requiredRefundSignatures = p2pk.requiredRefundSignatures

  assertSpendingConditionRules(
    pubkeys.length,
    refundKeys.length,
    requiredSignatures,
    requiredRefundSignatures,
    p2pk.locktime !== undefined
  )

  return {
    pubkeys,
    refundKeys,
    locktime: p2pk.locktime,
    requiredSignatures: requiredSignatures > 1 ? requiredSignatures : undefined,
    requiredRefundSignatures:
      requiredRefundSignatures !== undefined && requiredRefundSignatures > 1
        ? requiredRefundSignatures
        : undefined,
    additionalTags: p2pk.additionalTags?.length ? p2pk.additionalTags : undefined,
    sigFlag: p2pk.sigFlag,
    hashlock: p2pk.hashlock,
  }
}

function toUInt64(amount: AmountLike): bigint {
  if (amount instanceof Amount) return amount.toBigInt()
  if (typeof amount === 'bigint') return amount
  if (typeof amount === 'number') return BigInt(amount)
  if (typeof amount === 'string') return BigInt(amount)
  throw new Error('Amount is not AmountLike')
}

function toKeyset(keyset: HasKeysetKeys): Keyset {
  const keys: Record<string, string> = {}
  for (const [k, v] of Object.entries(keyset.keys)) {
    keys[String(k)] = v
  }
  return { id: keyset.id, keys }
}

function toNitroP2PKOptions(
  p2pk: P2PKOptions
): { nitro: NitroP2PKOptions; ephemeralE?: string } {
  const normalized = normalizeP2PKOptions(p2pk)
  let lockKeys = normalized.pubkeys
  let refundKeys = normalized.refundKeys

  let ephemeralE: string | undefined
  if (p2pk.blindKeys) {
    const numLock = lockKeys.length
    const ordered = [...lockKeys, ...refundKeys]
    // TODO: do it on the native side
    const { blinded, Ehex } = deriveP2BKBlindedPubkeys(ordered)
    lockKeys = blinded.slice(0, numLock)
    refundKeys = blinded.slice(numLock)
    ephemeralE = Ehex
  }

  if (normalized.additionalTags) {
    for (const tag of normalized.additionalTags) assertValidTagKey(tag[0])
  }

  return {
    nitro: {
      pubkeys: lockKeys,
      locktime: normalized.locktime,
      refundKeys: refundKeys.length > 0 ? refundKeys : undefined,
      requiredSignatures: normalized.requiredSignatures,
      requiredRefundSignatures: normalized.requiredRefundSignatures,
      additionalTags: normalized.additionalTags?.map((tag) => Array.from(tag)),
      blindKeys: undefined,
      sigFlag: normalized.sigFlag,
      hashlock: normalized.hashlock,
    },
    ephemeralE,
  }
}

function uint8ArrayToArrayBuffer(arr: Uint8Array): ArrayBuffer {
  return arr.buffer.slice(arr.byteOffset, arr.byteOffset + arr.byteLength) as ArrayBuffer
}

function nativeToOutputData(
  native: {
    blindedMessage: { amount: bigint; B_: string; id: string }
    blindingFactor: string
    secret: string
  },
  ephemeralE?: string
): OutputData {
  const data = new OutputData(
    {
      amount: Number(native.blindedMessage.amount),
      B_: native.blindedMessage.B_,
      id: native.blindedMessage.id,
    },
    BigInt('0x' + native.blindingFactor),
    new TextEncoder().encode(native.secret)
  )
  if (ephemeralE !== undefined) {
    ;(data as unknown as { ephemeralE?: string }).ephemeralE = ephemeralE
  }
  return data
}


export class NativeOutputCreator implements OutputDataCreator {
  private readonly _native: OutputCreator

  constructor() {
    this._native = NitroModules.createHybridObject<OutputCreator>('OutputCreator')
  }

  createP2PKData(
    p2pk: P2PKOptions,
    amount: AmountLike,
    keyset: HasKeysetKeys,
    customSplit?: AmountLike[]
  ): OutputData[] {
    const { nitro, ephemeralE } = toNitroP2PKOptions(p2pk)
    return this._native
      .createP2PKData(nitro, toUInt64(amount), toKeyset(keyset), customSplit?.map(toUInt64))
      .map((n) => nativeToOutputData(n, ephemeralE))
  }

  createSingleP2PKData(
    p2pk: P2PKOptions,
    amount: AmountLike,
    keysetId: string
  ): OutputData {
    const { nitro, ephemeralE } = toNitroP2PKOptions(p2pk)
    return nativeToOutputData(
      this._native.createSingleP2PKData(nitro, toUInt64(amount), keysetId),
      ephemeralE
    )
  }

  createRandomData(
    amount: AmountLike,
    keyset: HasKeysetKeys,
    customSplit?: AmountLike[]
  ): OutputData[] {
    return this._native
      .createRandomData(toUInt64(amount), toKeyset(keyset), customSplit?.map(toUInt64))
      .map((n) => nativeToOutputData(n))
  }

  createSingleRandomData(amount: AmountLike, keysetId: string): OutputData {
    return nativeToOutputData(
      this._native.createSingleRandomData(toUInt64(amount), keysetId)
    )
  }

  createDeterministicData(
    amount: AmountLike,
    seed: Uint8Array,
    counter: number,
    keyset: HasKeysetKeys,
    customSplit?: AmountLike[]
  ): OutputData[] {
    return this._native
      .createDeterministicData(
        toUInt64(amount),
        uint8ArrayToArrayBuffer(seed),
        BigInt(counter),
        toKeyset(keyset),
        customSplit?.map(toUInt64)
      )
      .map((n) => nativeToOutputData(n))
  }

  createSingleDeterministicData(
    amount: AmountLike,
    seed: Uint8Array,
    counter: number,
    keysetId: string
  ): OutputData {
    return nativeToOutputData(
      this._native.createSingleDeterministicData(
        toUInt64(amount),
        uint8ArrayToArrayBuffer(seed),
        BigInt(counter),
        keysetId
      )
    )
  }
}
