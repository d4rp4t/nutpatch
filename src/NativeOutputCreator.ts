import { NitroModules } from 'react-native-nitro-modules'
import {
  OutputData,
  type OutputDataCreator,
  type AmountLike,
  type HasKeysetKeys,
  type P2PKOptions,
  Amount,
} from '@cashu/cashu-ts'
import type {
  Keyset,
  NitroP2PKOptions,
  OutputCreator,
} from './specs/OutputCreator.nitro'
import { assertValidTagKey, normalizeP2PKOptions } from './p2pk-utils'

function toUInt64(amount: AmountLike): bigint {
  if (amount instanceof Amount) return amount.toBigInt()
  if (typeof amount === 'bigint') return amount
  if (typeof amount === 'number') {
    if (!Number.isSafeInteger(amount)) {
      throw new Error(`Amount is not a safe integer: ${amount}`)
    }
    return BigInt(amount)
  }
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

function toNitroP2PKOptions(p2pk: P2PKOptions): NitroP2PKOptions {
  const normalized = normalizeP2PKOptions(p2pk)

  if (normalized.additionalTags) {
    for (const tag of normalized.additionalTags) assertValidTagKey(tag[0])
  }

  return {
    pubkeys: normalized.pubkeys,
    locktime: normalized.locktime,
    refundKeys:
      normalized.refundKeys.length > 0 ? normalized.refundKeys : undefined,
    requiredSignatures: normalized.requiredSignatures,
    requiredRefundSignatures: normalized.requiredRefundSignatures,
    additionalTags: normalized.additionalTags?.map((tag) => Array.from(tag)),
    blindKeys: p2pk.blindKeys,
    sigFlag: normalized.sigFlag,
    hashlock: normalized.hashlock,
  }
}

function uint8ArrayToArrayBuffer(arr: Uint8Array): ArrayBuffer {
  return arr.buffer.slice(
    arr.byteOffset,
    arr.byteOffset + arr.byteLength
  ) as ArrayBuffer
}

function nativeToOutputData(native: {
  blindedMessage: { amount: bigint; B_: string; id: string }
  blindingFactor: string
  secret: string
  ephemeralE: string
}): OutputData {
  return new OutputData(
    {
      amount: Amount.from(native.blindedMessage.amount),
      B_: native.blindedMessage.B_,
      id: native.blindedMessage.id,
    },
    BigInt('0x' + native.blindingFactor),
    new TextEncoder().encode(native.secret),
    native.ephemeralE.length > 0 ? native.ephemeralE : undefined
  )
}

export class NativeOutputCreator implements OutputDataCreator {
  private readonly _native: OutputCreator

  constructor() {
    this._native =
      NitroModules.createHybridObject<OutputCreator>('OutputCreator')
  }

  createP2PKData(
    p2pk: P2PKOptions,
    amount: AmountLike,
    keyset: HasKeysetKeys,
    customSplit?: AmountLike[]
  ): OutputData[] {
    return this._native
      .createP2PKData(
        toNitroP2PKOptions(p2pk),
        toUInt64(amount),
        toKeyset(keyset),
        customSplit?.map(toUInt64)
      )
      .map(nativeToOutputData)
  }

  createSingleP2PKData(
    p2pk: P2PKOptions,
    amount: AmountLike,
    keysetId: string
  ): OutputData {
    return nativeToOutputData(
      this._native.createSingleP2PKData(
        toNitroP2PKOptions(p2pk),
        toUInt64(amount),
        keysetId
      )
    )
  }

  createRandomData(
    amount: AmountLike,
    keyset: HasKeysetKeys,
    customSplit?: AmountLike[]
  ): OutputData[] {
    return this._native
      .createRandomData(
        toUInt64(amount),
        toKeyset(keyset),
        customSplit?.map(toUInt64)
      )
      .map(nativeToOutputData)
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
      .map(nativeToOutputData)
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
