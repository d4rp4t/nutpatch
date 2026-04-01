import type { WeierstrassPoint } from '@noble/curves/abstract/weierstrass'
import { secp256k1 } from '@noble/curves/secp256k1'
import { bytesToHex } from '@noble/curves/utils'
import { NitroModules } from 'react-native-nitro-modules'
import type { Crypto } from '../specs/Crypto.nitro'

export type RawBlindedMessage = {
  B_: WeierstrassPoint<bigint>
  r: bigint
  secret: Uint8Array
}

let _instance: Crypto | null = null
function getInstance(): Crypto {
  if (!_instance) {
    _instance = NitroModules.createHybridObject<Crypto>('Crypto')
  }
  return _instance
}

function toBuffer(u8: Uint8Array): ArrayBuffer {
  return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength)
}

function toPoint(buf: ArrayBuffer): WeierstrassPoint<bigint> {
  return secp256k1.Point.fromHex(bytesToHex(new Uint8Array(buf)))
}

function bigintToBuffer(n: bigint): ArrayBuffer {
  const buf = new Uint8Array(32)
  for (let i = 31; i >= 0; i--) {
    buf[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return buf.buffer
}

export function hashToCurve(secret: Uint8Array): WeierstrassPoint<bigint> {
  return toPoint(getInstance().hashToCurve(toBuffer(secret)))
}

export function blindMessage(secret: Uint8Array, r?: bigint): RawBlindedMessage {
  if (r === undefined) {
    r = secp256k1.Point.Fn.fromBytes(secp256k1.utils.randomSecretKey())
  }
  const B_ = toPoint(getInstance().blind(toBuffer(secret), bigintToBuffer(r)))
  return { B_, r, secret }
}

export function unblindSignature(
  C_: WeierstrassPoint<bigint>,
  r: bigint,
  A: WeierstrassPoint<bigint>,
): WeierstrassPoint<bigint> {
  return toPoint(
    getInstance().unblind(
      toBuffer(C_.toRawBytes(true)),
      bigintToBuffer(r),
      toBuffer(A.toRawBytes(true)),
    ),
  )
}
