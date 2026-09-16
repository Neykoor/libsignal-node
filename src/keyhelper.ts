import * as nodeCrypto from "crypto"
import * as curve from "./curve"
import type { KeyPair } from "./curve"

function isNonNegativeInteger(n: number): boolean {
  return typeof n === "number" && n % 1 === 0 && n >= 0
}

export interface SignedPreKey {
  keyId: number
  keyPair: KeyPair
  signature: Buffer
  createdAt: number
}

export interface PreKey {
  keyId: number
  keyPair: KeyPair
}

export const DEFAULT_SIGNED_PRE_KEY_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

export function shouldRotateSignedPreKey(
  createdAt: number,
  maxAgeMs: number = DEFAULT_SIGNED_PRE_KEY_MAX_AGE_MS
): boolean {
  if (!isNonNegativeInteger(createdAt)) {
    throw new TypeError("Invalid argument for createdAt: " + createdAt)
  }

  if (!isNonNegativeInteger(maxAgeMs)) {
    throw new TypeError("Invalid argument for maxAgeMs: " + maxAgeMs)
  }

  return Date.now() - createdAt >= maxAgeMs
}

export const generateIdentityKeyPair = curve.generateKeyPair

export function generateRegistrationId(): number {
  let registrationId: number
  do {
    registrationId = nodeCrypto.randomBytes(2).readUInt16BE(0) & 0x3fff
  } while (registrationId === 0)

  return registrationId
}

export function generateSignedPreKey(identityKeyPair: KeyPair, signedKeyId: number): SignedPreKey {
  if (
    !(identityKeyPair.privKey instanceof Buffer) ||
    identityKeyPair.privKey.byteLength !== 32 ||
    !(identityKeyPair.pubKey instanceof Buffer) ||
    identityKeyPair.pubKey.byteLength !== 33
  ) {
    throw new TypeError("Invalid argument for identityKeyPair")
  }

  if (!isNonNegativeInteger(signedKeyId)) {
    throw new TypeError("Invalid argument for signedKeyId: " + signedKeyId)
  }

  const keyPair = curve.generateKeyPair()
  const sig = curve.calculateSignature(identityKeyPair.privKey, keyPair.pubKey)

  return {
    keyId: signedKeyId,
    keyPair,
    signature: sig,
    createdAt: Date.now()
  }
}

export function generatePreKey(keyId: number): PreKey {
  if (!isNonNegativeInteger(keyId)) {
    throw new TypeError("Invalid argument for keyId: " + keyId)
  }

  const keyPair = curve.generateKeyPair()

  return {
    keyId,
    keyPair
  }
}

export async function generateSignedPreKeyAsync(identityKeyPair: KeyPair, signedKeyId: number): Promise<SignedPreKey> {
  if (
    !(identityKeyPair.privKey instanceof Buffer) ||
    identityKeyPair.privKey.byteLength !== 32 ||
    !(identityKeyPair.pubKey instanceof Buffer) ||
    identityKeyPair.pubKey.byteLength !== 33
  ) {
    throw new TypeError("Invalid argument for identityKeyPair")
  }

  if (!isNonNegativeInteger(signedKeyId)) {
    throw new TypeError("Invalid argument for signedKeyId: " + signedKeyId)
  }

  const keyPair = await curve.generateKeyPairAsync()
  const sig = curve.calculateSignature(identityKeyPair.privKey, keyPair.pubKey)

  return {
    keyId: signedKeyId,
    keyPair,
    signature: sig,
    createdAt: Date.now()
  }
}

export async function generatePreKeyAsync(keyId: number): Promise<PreKey> {
  if (!isNonNegativeInteger(keyId)) {
    throw new TypeError("Invalid argument for keyId: " + keyId)
  }

  const keyPair = await curve.generateKeyPairAsync()

  return {
    keyId,
    keyPair
  }
}

export interface PreKeyBatchOptions {
  concurrency?: number
}

export async function generatePreKeysBatch(
  startId: number,
  count: number,
  options: PreKeyBatchOptions = {}
): Promise<PreKey[]> {
  if (!isNonNegativeInteger(startId)) {
    throw new TypeError("Invalid argument for startId: " + startId)
  }

  if (!isNonNegativeInteger(count) || count === 0) {
    throw new TypeError("Invalid argument for count: " + count)
  }

  const concurrency = Math.max(1, Math.min(options.concurrency ?? 8, count))
  const results: PreKey[] = new Array(count)
  let next = 0

  async function worker(): Promise<void> {
    for (;;) {
      const i = next++
      if (i >= count) {
        return
      }
      results[i] = await generatePreKeyAsync(startId + i)
    }
  }

  await Promise.all(Array.from({ length: concurrency }, worker))
  return results
}
