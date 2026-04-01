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
}
