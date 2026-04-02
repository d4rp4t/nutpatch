import { type HybridObject } from 'react-native-nitro-modules'

export interface Crypto extends HybridObject<{
  ios: 'c++'
  android: 'c++'
}> {
  hashToCurve(message: ArrayBuffer): ArrayBuffer
  blind(message: ArrayBuffer, blindingFactor: ArrayBuffer): ArrayBuffer
  unblind(
    blindedSignature: ArrayBuffer,
    blindingFactor: ArrayBuffer,
    mintPubkey: ArrayBuffer
  ): ArrayBuffer

  computeSha256(message: ArrayBuffer): ArrayBuffer
  hashE(pubkeys: ArrayBuffer[]): ArrayBuffer

  schnorrSign(seckey: ArrayBuffer, msg: ArrayBuffer): ArrayBuffer
  schnorrVerify(sig: ArrayBuffer, msg: ArrayBuffer, xonlyPubkey: ArrayBuffer): boolean

  seckeyGenerate(): ArrayBuffer
  createBlindSignature(B_: ArrayBuffer, seckey: ArrayBuffer): ArrayBuffer
}
