import { timingSafeEqual } from "crypto"
import type { KeyPair } from "./curve"
import type { Direction } from "./direction"
import type { SignedPreKey } from "./keyhelper"
import { getLogger } from "./logger"
import type { PreKeyPoolStorage } from "./prekey-pool"
import { SessionRecord } from "./session-record"
import type { SenderKeyName } from "./sender-key-name"
import { SenderKeyRecord } from "./sender-key-record"
import type { IdentityChangedCallback, IdentityTrustPolicy, SenderKeyStore, SignalStorage } from "./types"

function safeEqual(a: Buffer, b: Buffer): boolean {
  if (a.byteLength !== b.byteLength) {
    return false
  }

  return timingSafeEqual(a, b)
}

const DEFAULT_SIGNED_PRE_KEY_GRACE_PERIOD_MS = 3 * 24 * 60 * 60 * 1000

export interface MemorySignalStorageOptions {
  identityTrustPolicy?: IdentityTrustPolicy
  onIdentityChanged?: IdentityChangedCallback
}

export class MemorySignalStorage implements SignalStorage, PreKeyPoolStorage, SenderKeyStore {
  private identityKeyPair: KeyPair
  private registrationId: number
  private sessions = new Map<string, SessionRecord>()
  private preKeys = new Map<number, KeyPair>()
  private publishedPreKeys = new Set<number>()
  private signedPreKeys = new Map<number, KeyPair>()
  private trustedIdentities = new Map<string, Buffer>()
  private senderKeys = new Map<string, SenderKeyRecord>()
  private retiredSignedPreKeys = new Map<number, number>()
  private nextPreKeyId = 1
  private latestSignedPreKey: SignedPreKey | undefined
  private signedPreKeyGracePeriodMs: number
  private identityTrustPolicy: IdentityTrustPolicy
  private onIdentityChanged: IdentityChangedCallback | undefined
  private preKeyRemovedListeners = new Set<(id: number) => void>()

  constructor(
    identityKeyPair: KeyPair,
    registrationId: number,
    signedPreKeyGracePeriodMs: number = DEFAULT_SIGNED_PRE_KEY_GRACE_PERIOD_MS,
    options: MemorySignalStorageOptions = {}
  ) {
    this.identityKeyPair = identityKeyPair
    this.registrationId = registrationId
    this.signedPreKeyGracePeriodMs = signedPreKeyGracePeriodMs
    this.identityTrustPolicy = options.identityTrustPolicy ?? "tofu"
    this.onIdentityChanged = options.onIdentityChanged
  }

  async loadSession(id: string): Promise<SessionRecord | undefined> {
    const stored = this.sessions.get(id)
    return stored ? SessionRecord.deserialize(stored.serialize()) : undefined
  }

  async storeSession(id: string, session: SessionRecord): Promise<void> {
    this.sessions.set(id, session)
  }

  async loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord | undefined> {
    const stored = this.senderKeys.get(senderKeyName.serialize())
    return stored ? SenderKeyRecord.deserialize(stored.serialize()) : undefined
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
      if (this.identityTrustPolicy === "strict") {
        return false
      }

      this.trustedIdentities.set(identifier, Buffer.from(identityKey))
      return true
    }

    return safeEqual(existing, identityKey)
  }

  async saveIdentity(identifier: string, identityKey: Buffer): Promise<boolean> {
    const existing = this.trustedIdentities.get(identifier)
    const changed = !existing || !safeEqual(existing, identityKey)
    this.trustedIdentities.set(identifier, Buffer.from(identityKey))

    if (existing && changed) {
      this.removeSessionsForIdentifier(identifier)
      this.emitIdentityChanged(identifier, identityKey, existing)
    }

    return changed
  }

  async removeIdentity(identifier: string): Promise<void> {
    this.trustedIdentities.delete(identifier)
    this.removeSessionsForIdentifier(identifier)
  }

  loadIdentity(identifier: string): Buffer | undefined {
    const identityKey = this.trustedIdentities.get(identifier)
    return identityKey ? Buffer.from(identityKey) : undefined
  }

  listIdentities(): string[] {
    return Array.from(this.trustedIdentities.keys()).sort()
  }

  private emitIdentityChanged(identifier: string, identityKey: Buffer, previousIdentityKey: Buffer): void {
    if (!this.onIdentityChanged) {
      return
    }

    try {
      this.onIdentityChanged({
        identifier,
        identityKey: Buffer.from(identityKey),
        previousIdentityKey: Buffer.from(previousIdentityKey)
      })
    } catch (e) {
      getLogger().warn(`onIdentityChanged callback failed for ${identifier}`, e)
    }
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
    const removed = this.preKeys.delete(id)
    this.publishedPreKeys.delete(id)
    if (removed) {
      this.emitPreKeyRemoved(id)
    }
  }

  async getAvailablePreKeyCount(): Promise<number> {
    return this.listAvailablePreKeyIds().length
  }

  listAvailablePreKeyIds(): number[] {
    return Array.from(this.preKeys.keys())
      .filter((id) => !this.publishedPreKeys.has(id))
      .sort((a, b) => a - b)
  }

  reservePreKey(id: number): boolean {
    if (!this.preKeys.has(id) || this.publishedPreKeys.has(id)) {
      return false
    }

    this.publishedPreKeys.add(id)
    return true
  }

  releasePreKey(id: number): boolean {
    return this.publishedPreKeys.delete(id)
  }

  onPreKeyRemoved(listener: (id: number) => void): () => void {
    this.preKeyRemovedListeners.add(listener)
    return () => {
      this.preKeyRemovedListeners.delete(listener)
    }
  }

  private emitPreKeyRemoved(id: number): void {
    for (const listener of this.preKeyRemovedListeners) {
      try {
        listener(id)
      } catch (e) {
        getLogger().warn(`onPreKeyRemoved listener failed for prekey ${id}`, e)
      }
    }
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

  listPreKeyIds(): number[] {
    return Array.from(this.preKeys.keys()).sort((a, b) => a - b)
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
