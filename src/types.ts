import type { KeyPair } from "./curve"
import type { Direction } from "./direction"
import type { SenderKeyName } from "./sender-key-name"
import type { SenderKeyRecord } from "./sender-key-record"
import type { SessionRecord } from "./session-record"

export type { KeyPair }

/**
 * How an identity that has never been seen before is handled.
 *
 * - `tofu` (trust on first use): the first identity seen for an identifier is
 *   accepted and remembered. Changing it later is rejected until `saveIdentity`
 *   is called explicitly.
 * - `strict`: unknown identities are rejected. They must be trusted explicitly
 *   with `saveIdentity` before a session can be created.
 */
export type IdentityTrustPolicy = "tofu" | "strict"

export interface IdentityChangedEvent {
  identifier: string
  identityKey: Buffer
  previousIdentityKey?: Buffer
}

export type IdentityChangedCallback = (event: IdentityChangedEvent) => void

export interface SignalStorage {
  loadSession(id: string): Promise<SessionRecord | undefined>
  storeSession(id: string, session: SessionRecord): Promise<void>
  isTrustedIdentity(identifier: string, identityKey: Buffer, direction: Direction): Promise<boolean> | boolean
  saveIdentity?(identifier: string, identityKey: Buffer): Promise<boolean> | boolean
  removeIdentity?(identifier: string): Promise<void> | void
  loadIdentity?(identifier: string): Promise<Buffer | undefined> | Buffer | undefined
  listIdentities?(): Promise<string[]> | string[]
  loadPreKey(id?: number | string): Promise<KeyPair | undefined>
  removePreKey(id: number): Promise<void> | void
  loadSignedPreKey(id?: number | string): Promise<KeyPair | undefined> | KeyPair | undefined
  getOurRegistrationId(): Promise<number> | number
  getOurIdentity(): Promise<KeyPair> | KeyPair
}

export interface SenderKeyStore {
  loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord | undefined>
  storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void>
  removeSenderKey(senderKeyName: SenderKeyName): Promise<void> | void
}

export interface DeviceKeyBundle {
  registrationId: number
  identityKey: Buffer
  signedPreKey: {
    keyId: number
    publicKey: Buffer
    signature: Buffer
  }
  preKey?: {
    keyId: number
    publicKey: Buffer
  }
}

export interface IncomingPreKeyMessage {
  registrationId?: number
  identityKey: Buffer
  baseKey: Buffer
  preKeyId?: number
  signedPreKeyId?: number
  message: Buffer
}

export interface EncryptedMessage {
  type: number
  body: Buffer
  registrationId?: number
}
