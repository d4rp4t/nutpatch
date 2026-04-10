import type { AmountLike, HasKeysetKeys, OutputData, P2PKOptions } from '@cashu/cashu-ts'

export type { OutputCreator } from './specs/OutputCreator.nitro'
export { NativeOutputCreator } from './NativeOutputCreator'
export interface OutputDataCreator {
  createP2PKData(
    p2pk: P2PKOptions,
    amount: AmountLike,
    keyset: HasKeysetKeys,
    customSplit?: AmountLike[],
  ): OutputData[];

  createSingleP2PKData(p2pk: P2PKOptions, amount: AmountLike, keysetId: string): OutputData;

  createRandomData(
    amount: AmountLike,
    keyset: HasKeysetKeys,
    customSplit?: AmountLike[],
  ): OutputData[];

  createSingleRandomData(amount: AmountLike, keysetId: string): OutputData;

  createDeterministicData(
    amount: AmountLike,
    seed: Uint8Array,
    counter: number,
    keyset: HasKeysetKeys,
    customSplit?: AmountLike[],
  ): OutputData[];

  createSingleDeterministicData(
    amount: AmountLike,
    seed: Uint8Array,
    counter: number,
    keysetId: string,
  ): OutputData;
}