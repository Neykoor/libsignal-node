import { timingSafeEqual } from "crypto"
import type { KeyPair } from "./curve"
import type { Direction } from "./direction"
import type { SignedPreKey } from "./keyhelper"
import type { PreKeyPoolStorage } from "./prekey-pool"
import { SessionRecord } from "./session-record"
import type { SenderKeyName } from "./sender-key-name"
import { SenderKeyRecord } from "./sender-key-record"
import type { SenderKeyStore, SignalStorage } from "./types"

function safeEqual(a: Buffer, b: Buffer): boolean {
  if (a.byteLength !== b.byteLength) {
    return false
  }

  return timingSafeEqual(a, b)
}

const DEFAULT_SIGNED_PRE_KEY_GRACE_PERIOD_MS = 3 * 24 * 60 * 60 * 1000

export class MemorySignalStorage implements SignalStorage, PreKeyPoolStorage, SenderKeyStore {
  private identityKeyPair: KeyPair
  private registrationId: number
  private sessions = new Map<string, SessionRecord>()
  private preKeys = new Map<number, KeyPair>()
  private signedPreKeys = new Map<number, KeyPair>()
  private trustedIdentities = new Map<string, Buffer>()
  private senderKeys = new Map<string, SenderKeyRecord>()
  private retiredSignedPreKeys = new Map<number, number>()
  private nextPreKeyId = 1
  private latestSignedPreKey: SignedPreKey | undefined
  private signedPreKeyGracePeriodMs: number

  constructor(
    identityKeyPair: KeyPair,
    registrationId: number,
    signedPreKeyGracePeriodMs: number = DEFAULT_SIGNED_PRE_KEY_GRACE_PERIOD_MS
  ) {
    this.identityKeyPair = identityKeyPair
    this.registrationId = registrationId
    this.signedPreKeyGracePeriodMs = signedPreKeyGracePeriodMs
  }

  async loadSession(id: string): Promise<SessionRecord | undefined> {
    return this.sessions.get(id)
  }

  async storeSession(id: string, session: SessionRecord): Promise<void> {
    this.sessions.set(id, session)
  }

  async loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord | undefined> {
    return this.senderKeys.get(senderKeyName.serialize())
  }

  async storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void> {
    this.senderKeys.set(senderKeyName.serialize(), record)
  }

  async removeSenderKey(senderKeyName: SenderKeyName): Promise<void> {
    this.senderKeys.delete(senderKeyName.serialize())
  }

  async removeGroupSessions(groupId: string): Promise<void> {
    const prefix = `${groupId}::`
    for (const key of this.senderKeys.keys()) {
      if (key.startsWith(prefix)) {
        this.senderKeys.delete(key)
      }
    }
  }

  async isTrustedIdentity(identifier: string, identityKey: Buffer, _direction: Direction): Promise<boolean> {
    const existing = this.trustedIdentities.get(identifier)
    if (!existing) {
      this.trustedIdentities.set(identifier, identityKey)
      return true
    }

    return safeEqual(existing, identityKey)
  }

  async saveIdentity(identifier: string, identityKey: Buffer): Promise<boolean> {
    const existing = this.trustedIdentities.get(identifier)
    const changed = !existing || !safeEqual(existing, identityKey)
    this.trustedIdentities.set(identifier, identityKey)

    if (existing && changed) {
      this.removeSessionsForIdentifier(identifier)
    }

    return changed
  }

  async removeIdentity(identifier: string): Promise<void> {
    this.trustedIdentities.delete(identifier)
    this.removeSessionsForIdentifier(identifier)
  }

  private removeSessionsForIdentifier(identifier: string): void {
    const prefix = `${identifier}.`
    for (const key of this.sessions.keys()) {
      if (key === identifier || key.startsWith(prefix)) {
        this.sessions.delete(key)
      }
    }
  }

  async loadPreKey(id?: number | string): Promise<KeyPair | undefined> {
    if (id === undefined) {
      return undefined
    }

    return this.preKeys.get(Number(id))
  }

  async removePreKey(id: number): Promise<void> {
    this.preKeys.delete(id)
  }

  async loadSignedPreKey(id?: number | string): Promise<KeyPair | undefined> {
    if (id === undefined) {
      return undefined
    }

    return this.signedPreKeys.get(Number(id))
  }

  async getOurRegistrationId(): Promise<number> {
    return this.registrationId
  }

  async getOurIdentity(): Promise<KeyPair> {
    return this.identityKeyPair
  }

  storePreKey(id: number, keyPair: KeyPair): void {
    this.preKeys.set(id, keyPair)
  }

  storeSignedPreKey(idOrRecord: number | SignedPreKey, keyPair?: KeyPair): void {
    if (typeof idOrRecord === "number") {
      this.signedPreKeys.set(idOrRecord, keyPair!)
      return
    }

    if (this.latestSignedPreKey && this.latestSignedPreKey.keyId !== idOrRecord.keyId) {
      this.retiredSignedPreKeys.set(this.latestSignedPreKey.keyId, Date.now())
    }

    this.signedPreKeys.set(idOrRecord.keyId, idOrRecord.keyPair)
    this.latestSignedPreKey = idOrRecord
    this.pruneRetiredSignedPreKeys()
  }

  async removeSignedPreKey(id: number): Promise<void> {
    this.signedPreKeys.delete(id)
    this.retiredSignedPreKeys.delete(id)
  }

  private pruneRetiredSignedPreKeys(): void {
    const now = Date.now()
    for (const [id, retiredAt] of this.retiredSignedPreKeys) {
      if (now - retiredAt >= this.signedPreKeyGracePeriodMs) {
        this.signedPreKeys.delete(id)
        this.retiredSignedPreKeys.delete(id)
      }
    }
  }

  async getPreKeyCount(): Promise<number> {
    return this.preKeys.size
  }

  async getNextPreKeyId(): Promise<number> {
    return this.nextPreKeyId
  }

  async setNextPreKeyId(id: number): Promise<void> {
    this.nextPreKeyId = id
  }

  async loadLatestSignedPreKey(): Promise<SignedPreKey | undefined> {
    return this.latestSignedPreKey
  }
}
