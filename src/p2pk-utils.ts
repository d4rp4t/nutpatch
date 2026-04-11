import type { P2PKOptions, P2PKTag, SigFlag } from '@cashu/cashu-ts'

export const VALID_SIG_FLAGS = new Set<string>(['SIG_INPUTS', 'SIG_ALL'])

export const RESERVED_P2PK_TAGS = new Set([
  'locktime',
  'pubkeys',
  'n_sigs',
  'refund',
  'n_sigs_refund',
  'sigflag',
])

export function assertValidTagKey(key: string): void {
  if (!key || typeof key !== 'string') throw new Error('tag key must be a non empty string')
  if (RESERVED_P2PK_TAGS.has(key))
    throw new Error(`additionalTags must not use reserved key "${key}"`)
}

export function normalizePubkey(pk: string): string {
  const hex = pk.toLowerCase()
  if (hex.length === 66 && (hex.startsWith('02') || hex.startsWith('03'))) return hex
  if (hex.length === 64) return `02${hex}`
  throw new Error(
    `Invalid pubkey, expected 33 byte compressed or 32 byte x only, got length ${hex.length}`
  )
}

export function dedupeP2PKPubkeys(keys: string[]): string[] {
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

export function assertSigFlag(flag: string): void {
  if (!VALID_SIG_FLAGS.has(flag))
    throw new Error(`Invalid sigflag "${flag}": must be "SIG_INPUTS" or "SIG_ALL"`)
}

export function assertPositiveInteger(value: number, field: string): void {
  if (!Number.isInteger(value) || value < 1)
    throw new Error(`${field} must be a positive integer, got ${value}`)
}

export function assertSpendingConditionRules(
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

export type NormalizedP2PK = {
  pubkeys: string[]
  refundKeys: string[]
  locktime?: number
  requiredSignatures?: number
  requiredRefundSignatures?: number
  additionalTags?: P2PKTag[]
  sigFlag?: SigFlag
  hashlock?: string
}

export function normalizeP2PKOptions(p2pk: P2PKOptions): NormalizedP2PK {
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
