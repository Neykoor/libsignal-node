import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "crypto"
import * as fs from "fs"
import * as path from "path"
import type { KeyPair } from "./curve"
import type { Direction } from "./direction"
import * as keyhelper from "./keyhelper"
import type { SignedPreKey } from "./keyhelper"
import type { PreKeyPoolStorage } from "./prekey-pool"
import { SenderKeyRecord } from "./sender-key-record"
import type { SenderKeyName } from "./sender-key-name"
import { SessionRecord } from "./session-record"
import type { SenderKeyStore, SignalStorage } from "./types"

const DEFAULT_SIGNED_PRE_KEY_GRACE_PERIOD_MS = 3 * 24 * 60 * 60 * 1000
const DEFAULT_SAVE_DEBOUNCE_MS = 25
const ENCRYPTION_KEY_LENGTH = 32
const ENCRYPTION_ALGORITHM = "aes-256-gcm"
const ENCRYPTION_IV_LENGTH = 12

interface PersistedState {
  identityKeyPair: KeyPair
  registrationId: number
  nextPreKeyId: number
  latestSignedPreKey: SignedPreKey | undefined
  preKeys: Record<string, KeyPair>
  signedPreKeys: Record<string, KeyPair>
  retiredSignedPreKeys: Record<string, number>
  trustedIdentities: Record<string, Buffer>
  sessions: Record<string, Buffer>
  senderKeys: Record<string, ReturnType<SenderKeyRecord["serialize"]>>
}

interface FileSignalStorageOptions {
  signedPreKeyGracePeriodMs?: number
  saveDebounceMs?: number
  encryptionKey?: Buffer
}

interface EncryptedPayload {
  encrypted: true
  iv: string
  authTag: string
  data: string
}

function isEncryptedPayload(value: unknown): value is EncryptedPayload {
  return (
    !!value &&
    typeof value === "object" &&
    (value as { encrypted?: unknown }).encrypted === true &&
    typeof (value as { iv?: unknown }).iv === "string" &&
    typeof (value as { authTag?: unknown }).authTag === "string" &&
    typeof (value as { data?: unknown }).data === "string"
  )
}

function encryptPayload(plaintext: string, key: Buffer): string {
  const iv = randomBytes(ENCRYPTION_IV_LENGTH)
  const cipher = createCipheriv(ENCRYPTION_ALGORITHM, key, iv)
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf-8"), cipher.final()])
  const payload: EncryptedPayload = {
    encrypted: true,
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    data: ciphertext.toString("base64")
  }

  return JSON.stringify(payload)
}

function decryptPayload(payload: EncryptedPayload, key: Buffer): string {
  const decipher = createDecipheriv(ENCRYPTION_ALGORITHM, key, Buffer.from(payload.iv, "base64"))
  decipher.setAuthTag(Buffer.from(payload.authTag, "base64"))
  const plaintext = Buffer.concat([decipher.update(Buffer.from(payload.data, "base64")), decipher.final()])
  return plaintext.toString("utf-8")
}

function bufferReviver(_key: string, value: unknown): unknown {
  if (
    value &&
    typeof value === "object" &&
    (value as { type?: string }).type === "Buffer" &&
    Array.isArray((value as { data?: unknown }).data)
  ) {
    return Buffer.from((value as { data: number[] }).data)
  }

  return value
}

function safeEqual(a: Buffer, b: Buffer): boolean {
  if (a.byteLength !== b.byteLength) {
    return false
  }

  return timingSafeEqual(a, b)
}

export class FileSignalStorage implements SignalStorage, PreKeyPoolStorage, SenderKeyStore {
  private filePath: string
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
  private saveDebounceMs: number
  private encryptionKey: Buffer | undefined
  private saveTimer: ReturnType<typeof setTimeout> | undefined

  private constructor(
    filePath: string,
    identityKeyPair: KeyPair,
    registrationId: number,
    options: FileSignalStorageOptions
  ) {
    this.filePath = filePath
    this.identityKeyPair = identityKeyPair
    this.registrationId = registrationId
    this.signedPreKeyGracePeriodMs = options.signedPreKeyGracePeriodMs ?? DEFAULT_SIGNED_PRE_KEY_GRACE_PERIOD_MS
    this.saveDebounceMs = options.saveDebounceMs ?? DEFAULT_SAVE_DEBOUNCE_MS
    this.encryptionKey = options.encryptionKey
  }

  static create(filePath: string, options: FileSignalStorageOptions = {}): FileSignalStorage {
    if (options.encryptionKey && options.encryptionKey.length !== ENCRYPTION_KEY_LENGTH) {
      throw new RangeError(`encryptionKey must be ${ENCRYPTION_KEY_LENGTH} bytes`)
    }

    fs.mkdirSync(path.dirname(filePath), { recursive: true })

    if (fs.existsSync(filePath)) {
      const raw = fs.readFileSync(filePath, "utf-8")
      const parsed: unknown = JSON.parse(raw)

      let json: string
      if (isEncryptedPayload(parsed)) {
        if (!options.encryptionKey) {
          throw new Error("File is encrypted; encryptionKey is required")
        }

        json = decryptPayload(parsed, options.encryptionKey)
      } else {
        json = raw
      }

      const data: PersistedState = JSON.parse(json, bufferReviver)
      const storage = new FileSignalStorage(filePath, data.identityKeyPair, data.registrationId, options)
      storage.applySnapshot(data)
      return storage
    }

    const identityKeyPair = keyhelper.generateIdentityKeyPair()
    const registrationId = keyhelper.generateRegistrationId()
    const storage = new FileSignalStorage(filePath, identityKeyPair, registrationId, options)
    storage.save()
    return storage
  }

  private applySnapshot(data: PersistedState): void {
    this.nextPreKeyId = data.nextPreKeyId ?? 1
    this.latestSignedPreKey = data.latestSignedPreKey

    for (const [id, keyPair] of Object.entries(data.preKeys ?? {})) {
      this.preKeys.set(Number(id), keyPair)
    }

    for (const [id, keyPair] of Object.entries(data.signedPreKeys ?? {})) {
      this.signedPreKeys.set(Number(id), keyPair)
    }

    for (const [id, retiredAt] of Object.entries(data.retiredSignedPreKeys ?? {})) {
      this.retiredSignedPreKeys.set(Number(id), retiredAt)
    }

    for (const [identifier, key] of Object.entries(data.trustedIdentities ?? {})) {
      this.trustedIdentities.set(identifier, key)
    }

    for (const [id, buf] of Object.entries(data.sessions ?? {})) {
      this.sessions.set(id, SessionRecord.deserialize(buf))
    }

    for (const [id, record] of Object.entries(data.senderKeys ?? {})) {
      this.senderKeys.set(id, SenderKeyRecord.deserialize(record))
    }
  }

  private toSnapshot(): PersistedState {
    const sessions: Record<string, Buffer> = {}
    for (const [id, record] of this.sessions) {
      sessions[id] = record.serialize()
    }

    const senderKeys: Record<string, ReturnType<SenderKeyRecord["serialize"]>> = {}
    for (const [id, record] of this.senderKeys) {
      senderKeys[id] = record.serialize()
    }

    return {
      identityKeyPair: this.identityKeyPair,
      registrationId: this.registrationId,
      nextPreKeyId: this.nextPreKeyId,
      latestSignedPreKey: this.latestSignedPreKey,
      preKeys: Object.fromEntries(this.preKeys),
      signedPreKeys: Object.fromEntries(this.signedPreKeys),
      retiredSignedPreKeys: Object.fromEntries(this.retiredSignedPreKeys),
      trustedIdentities: Object.fromEntries(this.trustedIdentities),
      sessions,
      senderKeys
    }
  }

  private save(): void {
    const json = JSON.stringify(this.toSnapshot())
    const payload = this.encryptionKey ? encryptPayload(json, this.encryptionKey) : json
    const tmpPath = `${this.filePath}.tmp`
    fs.writeFileSync(tmpPath, payload)
    fs.renameSync(tmpPath, this.filePath)
  }

  private scheduleSave(): void {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer)
    }

    this.saveTimer = setTimeout(() => {
      this.saveTimer = undefined
      this.save()
    }, this.saveDebounceMs)
  }

  flush(): void {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer)
      this.saveTimer = undefined
    }

    this.save()
  }

  async loadSession(id: string): Promise<SessionRecord | undefined> {
    return this.sessions.get(id)
  }

  async storeSession(id: string, session: SessionRecord): Promise<void> {
    this.sessions.set(id, session)
    this.scheduleSave()
  }

  async loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord | undefined> {
    return this.senderKeys.get(senderKeyName.serialize())
  }

  async storeSenderKey(senderKeyName: SenderKeyName, record: SenderKeyRecord): Promise<void> {
    this.senderKeys.set(senderKeyName.serialize(), record)
    this.scheduleSave()
  }

  async removeSenderKey(senderKeyName: SenderKeyName): Promise<void> {
    this.senderKeys.delete(senderKeyName.serialize())
    this.scheduleSave()
  }

  async removeGroupSessions(groupId: string): Promise<void> {
    const prefix = `${groupId}::`
    for (const key of this.senderKeys.keys()) {
      if (key.startsWith(prefix)) {
        this.senderKeys.delete(key)
      }
    }
    this.scheduleSave()
  }

  async isTrustedIdentity(identifier: string, identityKey: Buffer, _direction: Direction): Promise<boolean> {
    const existing = this.trustedIdentities.get(identifier)
    if (!existing) {
      this.trustedIdentities.set(identifier, identityKey)
      this.scheduleSave()
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

    this.scheduleSave()
    return changed
  }

  async removeIdentity(identifier: string): Promise<void> {
    this.trustedIdentities.delete(identifier)
    this.removeSessionsForIdentifier(identifier)
    this.scheduleSave()
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
    this.scheduleSave()
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
    this.scheduleSave()
  }

  storeSignedPreKey(idOrRecord: number | SignedPreKey, keyPair?: KeyPair): void {
    if (typeof idOrRecord === "number") {
      this.signedPreKeys.set(idOrRecord, keyPair!)
      this.scheduleSave()
      return
    }

    if (this.latestSignedPreKey && this.latestSignedPreKey.keyId !== idOrRecord.keyId) {
      this.retiredSignedPreKeys.set(this.latestSignedPreKey.keyId, Date.now())
    }

    this.signedPreKeys.set(idOrRecord.keyId, idOrRecord.keyPair)
    this.latestSignedPreKey = idOrRecord
    this.pruneRetiredSignedPreKeys()
    this.scheduleSave()
  }

  async removeSignedPreKey(id: number): Promise<void> {
    this.signedPreKeys.delete(id)
    this.retiredSignedPreKeys.delete(id)
    this.scheduleSave()
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
    this.scheduleSave()
  }

  async loadLatestSignedPreKey(): Promise<SignedPreKey | undefined> {
    return this.latestSignedPreKey
  }
                     }
