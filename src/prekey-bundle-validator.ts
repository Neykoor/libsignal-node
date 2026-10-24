import type { DeviceKeyBundle, IncomingPreKeyMessage } from "./types"
import { PreKeyError } from "./errors"

const MIN_REGISTRATION_ID = 1
const MAX_REGISTRATION_ID = 0x3fff
const IDENTITY_KEY_LENGTH = 33
const PUBLIC_KEY_LENGTH = 33
const SIGNATURE_LENGTH = 64
export const MAX_KEY_ID = 0xffffff

function isNonNegativeInteger(n: unknown): n is number {
  return typeof n === "number" && Number.isInteger(n) && n >= 0
}

function assertBufferLength(value: unknown, length: number, field: string): void {
  if (!(value instanceof Uint8Array)) {
    throw new PreKeyError(`${field} must be a Uint8Array`)
  }

  if (value.byteLength !== length) {
    throw new PreKeyError(`${field} has invalid length: expected ${length}, got ${value.byteLength}`)
  }
}

function assertKeyId(value: unknown, field: string): void {
  if (!isNonNegativeInteger(value) || value > MAX_KEY_ID) {
    throw new PreKeyError(`${field} is out of range: ${String(value)}`)
  }
}

function assertRegistrationId(value: unknown): void {
  if (!isNonNegativeInteger(value) || value < MIN_REGISTRATION_ID || value > MAX_REGISTRATION_ID) {
    throw new PreKeyError(`Invalid registrationId: ${String(value)}`)
  }
}

export function assertValidDeviceKeyBundle(bundle: DeviceKeyBundle): void {
  if (!bundle || typeof bundle !== "object") {
    throw new PreKeyError("Device key bundle must be an object")
  }

  assertRegistrationId(bundle.registrationId)

  assertBufferLength(bundle.identityKey, IDENTITY_KEY_LENGTH, "identityKey")

  if (!bundle.signedPreKey || typeof bundle.signedPreKey !== "object") {
    throw new PreKeyError("Missing signedPreKey")
  }

  assertKeyId(bundle.signedPreKey.keyId, "signedPreKey.keyId")
  assertBufferLength(bundle.signedPreKey.publicKey, PUBLIC_KEY_LENGTH, "signedPreKey.publicKey")
  assertBufferLength(bundle.signedPreKey.signature, SIGNATURE_LENGTH, "signedPreKey.signature")

  if (bundle.preKey) {
    assertKeyId(bundle.preKey.keyId, "preKey.keyId")
    assertBufferLength(bundle.preKey.publicKey, PUBLIC_KEY_LENGTH, "preKey.publicKey")
  }
}

export function assertValidIncomingPreKeyMessage(message: IncomingPreKeyMessage): void {
  if (!message || typeof message !== "object") {
    throw new PreKeyError("Incoming prekey message must be an object")
  }

  assertBufferLength(message.identityKey, IDENTITY_KEY_LENGTH, "identityKey")
  assertBufferLength(message.baseKey, PUBLIC_KEY_LENGTH, "baseKey")

  if (!(message.message instanceof Uint8Array) || message.message.byteLength === 0) {
    throw new PreKeyError("message must be a non-empty Uint8Array")
  }

  if (message.registrationId !== undefined) {
    assertRegistrationId(message.registrationId)
  }

  if (message.preKeyId !== undefined) {
    assertKeyId(message.preKeyId, "preKeyId")
  }

  if (message.signedPreKeyId === undefined) {
    throw new PreKeyError("Missing signedPreKeyId")
  }

  assertKeyId(message.signedPreKeyId, "signedPreKeyId")
}
