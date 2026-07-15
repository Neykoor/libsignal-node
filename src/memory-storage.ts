import { timingSafeEqual } from "crypto"
import type { KeyPair } from "./curve"
import type { Direction } from "./direction"
import { SessionRecord } from "./session-record"
import type { SignalStorage } from "./types"

function safeEqual(a: Buffer, b: Buffer): boolean {
  if (a.byteLength !== b.byteLength) {
    return false
  }

  return timingSafeEqual(a, b)
}

export class MemorySignalStorage implements SignalStorage {
  private identityKeyPair: KeyPair
  private registrationId: number
  private sessions = new Map<string, SessionRecord>()
  private preKeys = new Map<number, KeyPair>()
  private signedPreKeys = new Map<number, KeyPair>()
  private trustedIdentities = new Map<string, Buffer>()

  constructor(identityKeyPair: KeyPair, registrationId: number) {
    this.identityKeyPair = identityKeyPair
    this.registrationId = registrationId
  }

  async loadSession(id: string): Promise<SessionRecord | undefined> {
    return this.sessions.get(id)
  }

  async storeSession(id: string, session: SessionRecord): Promise<void> {
    this.sessions.set(id, session)
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
    this.trustedIdentities.set(identifier, identityKey)
    return !existing || !safeEqual(existing, identityKey)
  }

  async removeIdentity(identifier: string): Promise<void> {
    this.trustedIdentities.delete(identifier)
    this.sessions.delete(identifier)
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

  storeSignedPreKey(id: number, keyPair: KeyPair): void {
    this.signedPreKeys.set(id, keyPair)
  }
}
