import { describe, expect, it } from 'vitest'
import {
  assertValidTagKey,
  dedupeP2PKPubkeys,
  normalizeP2PKOptions,
  normalizePubkey,
} from '../src/p2pk-utils'

const PK_A = '02' + 'a'.repeat(64)
const PK_A_ODD = '03' + 'a'.repeat(64)
const PK_B = '02' + 'b'.repeat(64)
const PK_C = '02' + 'c'.repeat(64)
const PK_XONLY = 'd'.repeat(64)

describe('normalizePubkey', () => {
  it('passes through compressed 02/03 keys lowercased', () => {
    expect(normalizePubkey(PK_A.toUpperCase())).toBe(PK_A)
    expect(normalizePubkey(PK_A_ODD)).toBe(PK_A_ODD)
  })

  it('prepends 02 to x-only 32-byte keys', () => {
    expect(normalizePubkey(PK_XONLY)).toBe('02' + PK_XONLY)
  })

  it('throws on malformed input', () => {
    expect(() => normalizePubkey('abcd')).toThrow(/Invalid pubkey/)
    expect(() => normalizePubkey('04' + 'a'.repeat(64))).toThrow(
      /Invalid pubkey/
    )
  })
})

describe('dedupeP2PKPubkeys', () => {
  it('dedupes by x-only portion, keeping first occurrence', () => {
    const result = dedupeP2PKPubkeys([PK_A, PK_A_ODD, PK_B])
    expect(result).toEqual([PK_A, PK_B])
  })

  it('preserves insertion order for unique keys', () => {
    expect(dedupeP2PKPubkeys([PK_B, PK_A, PK_C])).toEqual([PK_B, PK_A, PK_C])
  })
})

describe('assertValidTagKey', () => {
  it.each([
    'locktime',
    'pubkeys',
    'n_sigs',
    'refund',
    'n_sigs_refund',
    'sigflag',
  ])('rejects reserved key %s', (key) => {
    expect(() => assertValidTagKey(key)).toThrow(/reserved key/)
  })

  it('rejects empty or non-string keys', () => {
    expect(() => assertValidTagKey('')).toThrow(/non empty string/)
    // @ts-expect-error testing runtime guard
    expect(() => assertValidTagKey(null)).toThrow(/non empty string/)
  })

  it('accepts non-reserved keys', () => {
    expect(() => assertValidTagKey('custom')).not.toThrow()
  })
})

describe('normalizeP2PKOptions', () => {
  it('returns pubkeys as array even when single string given', () => {
    const n = normalizeP2PKOptions({ pubkey: PK_A })
    expect(n.pubkeys).toEqual([PK_A])
    expect(n.refundKeys).toEqual([])
  })

  it('deduplicates pubkeys and refund keys', () => {
    const n = normalizeP2PKOptions({
      pubkey: [PK_A, PK_A_ODD, PK_B],
      refundKeys: [PK_C, PK_C],
      locktime: 100,
    })
    expect(n.pubkeys).toEqual([PK_A, PK_B])
    expect(n.refundKeys).toEqual([PK_C])
  })

  it('throws when pubkey list is empty after dedupe', () => {
    expect(() => normalizeP2PKOptions({ pubkey: [] })).toThrow(
      /at least one pubkey/
    )
  })

  it('enforces 10-key total maximum', () => {
    const many = Array.from(
      { length: 11 },
      (_, i) => '02' + i.toString(16).padStart(2, '0').repeat(32)
    )
    expect(() => normalizeP2PKOptions({ pubkey: many })).toThrow(
      /Too many pubkeys/
    )
  })

  it('requires locktime when refund keys are present', () => {
    expect(() =>
      normalizeP2PKOptions({ pubkey: PK_A, refundKeys: [PK_B] })
    ).toThrow(/refund keys require a locktime/)
  })

  it('validates sigFlag', () => {
    expect(() =>
      normalizeP2PKOptions({ pubkey: PK_A, sigFlag: 'SIG_BOGUS' as never })
    ).toThrow(/Invalid sigflag/)
  })

  it('requires n_sigs <= main key count', () => {
    expect(() =>
      normalizeP2PKOptions({ pubkey: [PK_A, PK_B], requiredSignatures: 3 })
    ).toThrow(/exceeds available pubkeys/)
  })

  it('n_sigs_refund without refund keys throws', () => {
    expect(() =>
      normalizeP2PKOptions({ pubkey: PK_A, requiredRefundSignatures: 2 })
    ).toThrow(/requires refund keys/)
  })

  it('drops n_sigs when value equals 1 (default)', () => {
    const n = normalizeP2PKOptions({ pubkey: [PK_A, PK_B] })
    expect(n.requiredSignatures).toBeUndefined()
  })

  it('keeps n_sigs when > 1', () => {
    const n = normalizeP2PKOptions({
      pubkey: [PK_A, PK_B],
      requiredSignatures: 2,
    })
    expect(n.requiredSignatures).toBe(2)
  })

  it('passes through hashlock, locktime, sigFlag, additionalTags', () => {
    const n = normalizeP2PKOptions({
      pubkey: PK_A,
      hashlock: 'ff'.repeat(32),
      locktime: 42,
      sigFlag: 'SIG_ALL',
      additionalTags: [['memo', 'hello']],
    })
    expect(n.hashlock).toBe('ff'.repeat(32))
    expect(n.locktime).toBe(42)
    expect(n.sigFlag).toBe('SIG_ALL')
    expect(n.additionalTags).toEqual([['memo', 'hello']])
  })
})
