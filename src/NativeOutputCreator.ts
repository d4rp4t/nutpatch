import { NitroModules } from 'react-native-nitro-modules'
import {
  OutputData,
  type AmountLike,
  type HasKeysetKeys,
  type P2PKOptions, Amount,
} from '@cashu/cashu-ts'
import type { OutputCreator, Keyset, NitroP2PKOptions } from './specs/OutputCreator.nitro'
import type { OutputDataCreator } from './index'

function toUInt64(amount: AmountLike): bigint {
  if (amount instanceof Amount) return amount.toBigInt()
  if (typeof amount === 'bigint') return amount
  if (typeof amount === 'number') return BigInt(amount)
  if (typeof amount === 'string') return BigInt(amount)
  throw new Error("Amount is not AmountLike")
}

function toKeyset(keyset: HasKeysetKeys): Keyset {
  const keys: Record<string, string> = {}
  for (const [k, v] of Object.entries(keyset.keys)) {
    keys[String(k)] = v
  }
  return { id: keyset.id, keys }
}

function toNitroP2PKOptions(p2pk: P2PKOptions): NitroP2PKOptions {
  return {
    pubkeys: Array.isArray(p2pk.pubkey) ? p2pk.pubkey : [p2pk.pubkey],
    locktime: p2pk.locktime,
    refundKeys: p2pk.refundKeys,
    requiredSignatures: p2pk.requiredSignatures,
    requiredRefundSignatures: p2pk.requiredRefundSignatures,
    additionalTags: p2pk.additionalTags?.map((tag) => Array.from(tag)),
    blindKeys: p2pk.blindKeys,
    sigFlag: p2pk.sigFlag,
    hashlock: p2pk.hashlock,
  }
}

function hexToUint8Array(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

function uint8ArrayToArrayBuffer(arr: Uint8Array): ArrayBuffer {
  return arr.buffer.slice(arr.byteOffset, arr.byteOffset + arr.byteLength) as ArrayBuffer
}

function nativeToOutputData(native: {
  blindedMessage: { amount: bigint; B_: string; id: string }
  blindingFactor: string
  secret: string
}): OutputData {
  return new OutputData(
    {
      amount: Number(native.blindedMessage.amount),
      B_: native.blindedMessage.B_,
      id: native.blindedMessage.id,
    },
    BigInt('0x' + native.blindingFactor),
    hexToUint8Array(native.secret)
  )
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
      this._native.createSingleP2PKData(toNitroP2PKOptions(p2pk), toUInt64(amount), keysetId)
    )
  }

  createRandomData(
    amount: AmountLike,
    keyset: HasKeysetKeys,
    customSplit?: AmountLike[]
  ): OutputData[] {
    return this._native
      .createRandomData(toUInt64(amount), toKeyset(keyset), customSplit?.map(toUInt64))
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
