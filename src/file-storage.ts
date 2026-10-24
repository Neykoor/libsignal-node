import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from "crypto"
import * as fs from "fs"
import { hostname } from "os"
import * as path from "path"
import type { KeyPair } from "./curve"
import type { Direction } from "./direction"
import { FileSignalStorageConflictError, FileSignalStorageLockError } from "./errors"
import * as keyhelper from "./keyhelper"
import type { SignedPreKey } from "./keyhelper"
import { getLogger } from "./logger"
import { MAX_KEY_ID } from "./prekey-bundle-validator"
import type { PreKeyPoolStorage } from "./prekey-pool"
import { SenderKeyRecord } from "./sender-key-record"
import type { SenderKeyName } from "./sender-key-name"
import { SessionRecord } from "./session-record"
import type { IdentityChangedCallback, IdentityTrustPolicy, SenderKeyStore, SignalStorage } from "./types"

const DEFAULT_SIGNED_PRE_KEY_GRACE_PERIOD_MS = 3 * 24 * 60 * 60 * 1000
const DEFAULT_SAVE_DEBOUNCE_MS = 25
const DEFAULT_FILE_MODE = 0o600
const DEFAULT_LOCK_TIMEOUT_MS = 5000
const DEFAULT_STALE_LOCK_MS = 10 * 60 * 1000
const LOCK_RETRY_INTERVAL_MS = 25
const ENCRYPTION_KEY_LENGTH = 32
const ENCRYPTION_ALGORITHM = "aes-256-gcm"
const ENCRYPTION_IV_LENGTH = 12
const CURRENT_FORMAT_VERSION = 1
const LEGACY_FORMAT_VERSION = 1
const MIN_REGISTRATION_ID = 0
const MAX_REGISTRATION_ID = 0x3fff

interface PersistedState {
  formatVersion: number
  revision: number
  identityKeyPair: KeyPair
  registrationId: number
  nextPreKeyId: number
  latestSignedPreKey: SignedPreKey | undefined
  preKeys: Record<string, KeyPair>
  publishedPreKeyIds: number[]
  signedPreKeys: Record<string, KeyPair>
  retiredSignedPreKeys: Record<string, number>
  trustedIdentities: Record<string, Buffer>
  sessions: Record<string, Buffer>
  senderKeys: Record<string, ReturnType<SenderKeyRecord["serialize"]>>
}

export interface FileSignalStorageOptions {
  signedPreKeyGracePeriodMs?: number
  saveDebounceMs?: number
  encryptionKey?: Buffer
  identityTrustPolicy?: IdentityTrustPolicy
  onIdentityChanged?: IdentityChangedCallback
  /** Use a lock file to serialize access between processes. Defaults to true. */
  lock?: boolean
  /** How long to wait for a lock before failing. Defaults to 5000 ms. */
  lockTimeoutMs?: number
  /** Age after which a lock from an unreadable/dead owner is considered stale. */
  staleLockMs?: number
  /** Keep the previous snapshot in `<file>.bak`. Defaults to true. */
  backup?: boolean
  /** Mode used for the storage, lock and temporary files. Defaults to 0o600. */
  fileMode?: number
  /** Called when a debounced save fails. `flush()` still throws to the caller. */
  onSaveError?: (error: Error) => void
}

interface FileLockMetadata {
  token: string
  pid: number
  hostname: string
  createdAt: number
  filePath: string
}

interface LoadedState {
  data: PersistedState
  migrated: boolean
}

class CorruptStorageFileError extends Error {
  public readonly recoverable = true
}

class UnsupportedFormatVersionError extends Error {}

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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
}

function assertBuffer(value: unknown, field: string, length?: number): asserts value is Buffer {
  if (!Buffer.isBuffer(value)) {
    throw new Error(`${field} must be a Buffer`)
  }

  if (length !== undefined && value.byteLength !== length) {
    throw new Error(`${field} must be ${length} bytes, got ${value.byteLength}`)
  }
}

function assertInteger(value: unknown, field: string, min: number, max: number): asserts value is number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${field} must be an integer between ${min} and ${max}`)
  }
}

function assertKeyPair(value: unknown, field: string): asserts value is KeyPair {
  if (!isRecord(value)) {
    throw new Error(`${field} must be an object`)
  }

  assertBuffer(value.pubKey, `${field}.pubKey`, 33)
  assertBuffer(value.privKey, `${field}.privKey`, 32)
}

function assertKeyPairMap(value: unknown, field: string): asserts value is Record<string, KeyPair> {
  if (!isRecord(value)) {
    throw new Error(`${field} must be an object`)
  }

  for (const [id, keyPair] of Object.entries(value)) {
    assertInteger(Number(id), `${field} key id`, 0, MAX_KEY_ID)
    assertKeyPair(keyPair, `${field}.${id}`)
  }
}

function assertBufferMap(value: unknown, field: string, length?: number): asserts value is Record<string, Buffer> {
  if (!isRecord(value)) {
    throw new Error(`${field} must be an object`)
  }

  for (const [id, buffer] of Object.entries(value)) {
    assertBuffer(buffer, `${field}.${id}`, length)
  }
}

function assertRetiredSignedPreKeys(value: unknown): asserts value is Record<string, number> {
  if (!isRecord(value)) {
    throw new Error("retiredSignedPreKeys must be an object")
  }

  for (const [id, timestamp] of Object.entries(value)) {
    assertInteger(Number(id), "retiredSignedPreKeys key id", 0, MAX_KEY_ID)
    assertInteger(timestamp, `retiredSignedPreKeys.${id}`, 0, Number.MAX_SAFE_INTEGER)
  }
}

function assertNumberArray(value: unknown, field: string): asserts value is number[] {
  if (!Array.isArray(value)) {
    throw new Error(`${field} must be an array`)
  }

  for (const id of value) {
    assertInteger(id, `${field} id`, 0, MAX_KEY_ID)
  }
}

function assertSenderKeys(value: unknown): asserts value is Record<string, ReturnType<SenderKeyRecord["serialize"]>> {
  if (!isRecord(value)) {
    throw new Error("senderKeys must be an object")
  }

  for (const [id, record] of Object.entries(value)) {
    if (!Array.isArray(record) || record.some((state) => !isRecord(state))) {
      throw new Error(`senderKeys.${id} must be an array of sender key states`)
    }
  }
}

function assertSignedPreKey(value: unknown, field: string): asserts value is SignedPreKey {
  if (!isRecord(value)) {
    throw new Error(`${field} must be an object`)
  }

  assertInteger(value.keyId, `${field}.keyId`, 0, MAX_KEY_ID)
  assertKeyPair(value.keyPair, `${field}.keyPair`)
  assertBuffer(value.signature, `${field}.signature`, 64)
  assertInteger(value.createdAt, `${field}.createdAt`, 0, Number.MAX_SAFE_INTEGER)
}

function readLockMetadata(lockPath: string): FileLockMetadata | undefined {
  try {
    const parsed: unknown = JSON.parse(fs.readFileSync(lockPath, "utf-8"))
    if (
      !isRecord(parsed) ||
      typeof parsed.token !== "string" ||
      typeof parsed.pid !== "number" ||
      typeof parsed.hostname !== "string" ||
      typeof parsed.createdAt !== "number" ||
      typeof parsed.filePath !== "string"
    ) {
      return undefined
    }

    return {
      token: parsed.token,
      pid: parsed.pid,
      hostname: parsed.hostname,
      createdAt: parsed.createdAt,
      filePath: parsed.filePath
    }
  } catch {
    return undefined
  }
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) {
    return false
  }

  try {
    process.kill(pid, 0)
    return true
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM"
  }
}

function isLockStale(lockPath: string, staleLockMs: number): boolean {
  const metadata = readLockMetadata(lockPath)
  if (metadata && metadata.hostname === hostname()) {
    if (metadata.pid === process.pid) {
      const processStartedAt = Date.now() - process.uptime() * 1000
      if (metadata.createdAt < processStartedAt - 1000) {
        return true
      }
    }

    return !isProcessAlive(metadata.pid)
  }

  try {
    return Date.now() - fs.statSync(lockPath).mtimeMs > staleLockMs
  } catch {
    return false
  }
}

function sleepSync(ms: number): void {
  if (ms <= 0) {
    return
  }

  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
}

function chmodFile(filePath: string, mode: number): void {
  try {
    fs.chmodSync(filePath, mode)
  } catch {
    // Windows and some filesystems do not support POSIX modes.
  }
}

function cleanupTemporaryFiles(filePath: string): void {
  const directory = path.dirname(filePath)
  const prefix = `${path.basename(filePath)}.`
  try {
    for (const name of fs.readdirSync(directory)) {
      if (!name.startsWith(prefix) || !name.endsWith(".tmp")) {
        continue
      }

      const middle = name.slice(prefix.length, -".tmp".length)
      if (!/^\d+\.[0-9a-f]{12}$/.test(middle)) {
        continue
      }

      try {
        fs.rmSync(path.join(directory, name), { force: true })
      } catch {
        // Best effort: a stale temp file does not affect the main snapshot.
      }
    }
  } catch {
    // The directory is created before this call; ignore unexpected read errors.
  }
}

function syncFile(filePath: string): void {
  let fd: number | undefined
  try {
    fd = fs.openSync(filePath, "r")
    fs.fsyncSync(fd)
  } catch {
    // Durability is best-effort on filesystems that do not support fsync.
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd)
      } catch {
        // Ignore close errors.
      }
    }
  }
}

function syncDirectory(directory: string): void {
  let fd: number | undefined
  try {
    fd = fs.openSync(directory, "r")
    fs.fsyncSync(fd)
  } catch {
    // Opening or syncing a directory is not supported on every platform.
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd)
      } catch {
        // Ignore close errors.
      }
    }
  }
}

function acquireFileLock(filePath: string, options: FileSignalStorageOptions): string {
  const lockPath = `${filePath}.lock`
  const timeoutMs = Math.max(0, options.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS)
  const staleLockMs = Math.max(0, options.staleLockMs ?? DEFAULT_STALE_LOCK_MS)
  const deadline = Date.now() + timeoutMs

  for (;;) {
    const token = randomBytes(12).toString("hex")
    try {
      const metadata: FileLockMetadata = {
        token,
        pid: process.pid,
        hostname: hostname(),
        createdAt: Date.now(),
        filePath
      }
      fs.writeFileSync(lockPath, JSON.stringify(metadata), {
        flag: "wx",
        mode: options.fileMode ?? DEFAULT_FILE_MODE
      })
      return token
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code
      if (code !== "EEXIST") {
        try {
          fs.rmSync(lockPath, { force: true })
        } catch {
          // Ignore cleanup failures; the original error is more useful.
        }
        throw new FileSignalStorageLockError(lockPath, `Failed to acquire storage lock ${lockPath}: ${(e as Error).message}`)
      }
    }

    if (isLockStale(lockPath, staleLockMs)) {
      try {
        fs.rmSync(lockPath, { force: true })
        continue
      } catch {
        // Another process may have released or replaced the lock.
      }
    }

    if (Date.now() >= deadline) {
      const owner = readLockMetadata(lockPath)
      const ownerDescription = owner
        ? ` held by pid ${owner.pid} on ${owner.hostname} since ${new Date(owner.createdAt).toISOString()}`
        : ""
      throw new FileSignalStorageLockError(
        lockPath,
        `FileSignalStorage is already locked by another process${ownerDescription}: ${lockPath}`
      )
    }

    sleepSync(Math.min(LOCK_RETRY_INTERVAL_MS, Math.max(0, deadline - Date.now())))
  }
}

function releaseFileLock(lockPath: string, token: string): void {
  try {
    const metadata = readLockMetadata(lockPath)
    if (!metadata || metadata.token === token) {
      fs.rmSync(lockPath, { force: true })
    }
  } catch {
    // Lock cleanup is best-effort; a stale lock is detected on the next open.
  }
}

function loadPersistedState(
  filePath: string,
  encryptionKey: Buffer | undefined,
  validateRecords = true
): LoadedState {
  let raw: string
  try {
    raw = fs.readFileSync(filePath, "utf-8")
  } catch (e) {
    throw new Error(`Failed to read FileSignalStorage ${filePath}: ${(e as Error).message}`)
  }

  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (e) {
    throw new CorruptStorageFileError(`Invalid FileSignalStorage JSON in ${filePath}: ${(e as Error).message}`)
  }

  let json = raw
  if (isEncryptedPayload(parsed)) {
    if (!encryptionKey) {
      throw new Error("File is encrypted; encryptionKey is required")
    }

    try {
      json = decryptPayload(parsed, encryptionKey)
    } catch (e) {
      throw new Error(
        `Failed to decrypt FileSignalStorage ${filePath} (wrong encryptionKey or corrupted file): ${(e as Error).message}`
      )
    }
  }

  let rawState: unknown
  try {
    rawState = JSON.parse(json, bufferReviver)
  } catch (e) {
    throw new CorruptStorageFileError(`Invalid FileSignalStorage state in ${filePath}: ${(e as Error).message}`)
  }

  try {
    const migrated = !isRecord(rawState) || rawState.formatVersion !== CURRENT_FORMAT_VERSION
    const data = normalizePersistedState(rawState)

    if (validateRecords) {
      for (const [id, serialized] of Object.entries(data.sessions)) {
        try {
          SessionRecord.deserialize(serialized)
        } catch (e) {
          throw new Error(`Invalid session record for "${id}": ${(e as Error).message}`)
        }
      }

      for (const [id, serialized] of Object.entries(data.senderKeys)) {
        try {
          SenderKeyRecord.deserialize(serialized)
        } catch (e) {
          throw new Error(`Invalid sender key record for "${id}": ${(e as Error).message}`)
        }
      }
    }

    return { data, migrated }
  } catch (e) {
    if (e instanceof UnsupportedFormatVersionError) {
      throw e
    }

    throw new CorruptStorageFileError(`Invalid FileSignalStorage state in ${filePath}: ${(e as Error).message}`)
  }
}

function normalizePersistedState(value: unknown): PersistedState {
  if (!isRecord(value)) {
    throw new Error("state must be an object")
  }

  const formatVersion = value.formatVersion === undefined ? LEGACY_FORMAT_VERSION : value.formatVersion
  if (typeof formatVersion !== "number" || !Number.isInteger(formatVersion) || formatVersion < 1) {
    throw new Error(`invalid formatVersion: ${String(formatVersion)}`)
  }

  if (formatVersion > CURRENT_FORMAT_VERSION) {
    throw new UnsupportedFormatVersionError(
      `unsupported formatVersion ${formatVersion}; this build supports up to ${CURRENT_FORMAT_VERSION}`
    )
  }

  assertKeyPair(value.identityKeyPair, "identityKeyPair")
  assertInteger(value.registrationId, "registrationId", MIN_REGISTRATION_ID, MAX_REGISTRATION_ID)
  const revision = value.revision ?? 0
  assertInteger(revision, "revision", 0, Number.MAX_SAFE_INTEGER)
  const nextPreKeyId = value.nextPreKeyId ?? 1
  assertInteger(nextPreKeyId, "nextPreKeyId", 0, MAX_KEY_ID)

  const preKeys = value.preKeys ?? {}
  const publishedPreKeyIds = value.publishedPreKeyIds ?? []
  const signedPreKeys = value.signedPreKeys ?? {}
  const retiredSignedPreKeys = value.retiredSignedPreKeys ?? {}
  const trustedIdentities = value.trustedIdentities ?? {}
  const sessions = value.sessions ?? {}
  const senderKeys = value.senderKeys ?? {}

  assertKeyPairMap(preKeys, "preKeys")
  assertNumberArray(publishedPreKeyIds, "publishedPreKeyIds")
  assertKeyPairMap(signedPreKeys, "signedPreKeys")
  assertRetiredSignedPreKeys(retiredSignedPreKeys)
  assertBufferMap(trustedIdentities, "trustedIdentities", 33)
  assertBufferMap(sessions, "sessions")
  assertSenderKeys(senderKeys)

  if (value.latestSignedPreKey !== undefined) {
    assertSignedPreKey(value.latestSignedPreKey, "latestSignedPreKey")
  }

  return {
    formatVersion: CURRENT_FORMAT_VERSION,
    revision,
    identityKeyPair: value.identityKeyPair,
    registrationId: value.registrationId,
    nextPreKeyId,
    latestSignedPreKey: value.latestSignedPreKey,
    preKeys,
    publishedPreKeyIds: Array.from(new Set(publishedPreKeyIds)),
    signedPreKeys,
    retiredSignedPreKeys,
    trustedIdentities,
    sessions,
    senderKeys
  }
}

export class FileSignalStorage implements SignalStorage, PreKeyPoolStorage, SenderKeyStore {
  private filePath: string
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
  private revision = 0
  private latestSignedPreKey: SignedPreKey | undefined
  private signedPreKeyGracePeriodMs: number
  private saveDebounceMs: number
  private encryptionKey: Buffer | undefined
  private identityTrustPolicy: IdentityTrustPolicy
  private onIdentityChanged: IdentityChangedCallback | undefined
  private lockEnabled: boolean
  private lockTimeoutMs: number
  private staleLockMs: number
  private backupEnabled: boolean
  private fileMode: number
  private onSaveError: ((error: Error) => void) | undefined
  private preKeyRemovedListeners = new Set<(id: number) => void>()
  private saveTimer: ReturnType<typeof setTimeout> | undefined
  private dirty = false
  private closed = false

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
    this.encryptionKey = options.encryptionKey !== undefined ? Buffer.from(options.encryptionKey) : undefined
    this.identityTrustPolicy = options.identityTrustPolicy ?? "tofu"
    this.onIdentityChanged = options.onIdentityChanged
    this.lockEnabled = options.lock !== false
    this.lockTimeoutMs = options.lockTimeoutMs ?? DEFAULT_LOCK_TIMEOUT_MS
    this.staleLockMs = options.staleLockMs ?? DEFAULT_STALE_LOCK_MS
    this.backupEnabled = options.backup !== false
    this.fileMode = options.fileMode ?? DEFAULT_FILE_MODE
    this.onSaveError = options.onSaveError
  }

  static create(filePath: string, options: FileSignalStorageOptions = {}): FileSignalStorage {
    if (options.encryptionKey !== undefined && options.encryptionKey.byteLength !== ENCRYPTION_KEY_LENGTH) {
      throw new RangeError(`encryptionKey must be ${ENCRYPTION_KEY_LENGTH} bytes`)
    }

    fs.mkdirSync(path.dirname(filePath), { recursive: true })

    const lockPath = `${filePath}.lock`
    const lockToken = options.lock === false ? undefined : acquireFileLock(filePath, options)
    try {
      cleanupTemporaryFiles(filePath)
      const backupPath = options.backup === false ? undefined : `${filePath}.bak`
      let loaded: LoadedState | undefined

      if (fs.existsSync(filePath)) {
        try {
          loaded = loadPersistedState(filePath, options.encryptionKey)
        } catch (e) {
          if (!(e instanceof CorruptStorageFileError) || !backupPath || !fs.existsSync(backupPath)) {
            throw e
          }

          try {
            loaded = loadPersistedState(backupPath, options.encryptionKey)
            const corruptPath = `${filePath}.corrupt-${Date.now()}-${randomBytes(3).toString("hex")}`
            fs.renameSync(filePath, corruptPath)
            fs.copyFileSync(backupPath, filePath)
            syncFile(filePath)
            chmodFile(filePath, options.fileMode ?? DEFAULT_FILE_MODE)
            getLogger().warn(
              `Recovered FileSignalStorage ${filePath} from ${backupPath}; corrupt snapshot moved to ${corruptPath}`
            )
          } catch (backupError) {
            throw new Error(
              `${(e as Error).message}; backup recovery from ${backupPath} failed: ${(backupError as Error).message}`
            )
          }
        }
      } else if (backupPath && fs.existsSync(backupPath)) {
        try {
          loaded = loadPersistedState(backupPath, options.encryptionKey)
          fs.copyFileSync(backupPath, filePath)
          syncFile(filePath)
          chmodFile(filePath, options.fileMode ?? DEFAULT_FILE_MODE)
          getLogger().warn(`FileSignalStorage ${filePath} was missing; restored it from ${backupPath}`)
        } catch (backupError) {
          throw new Error(
            `FileSignalStorage ${filePath} is missing and backup recovery from ${backupPath} failed: ${
              (backupError as Error).message
            }`
          )
        }
      }

      if (loaded) {
        const storage = new FileSignalStorage(filePath, loaded.data.identityKeyPair, loaded.data.registrationId, options)
        storage.revision = loaded.data.revision
        storage.applySnapshot(loaded.data)

        if (loaded.migrated) {
          storage.dirty = true
          storage.saveUnlocked()
        }

        return storage
      }

      const identityKeyPair = keyhelper.generateIdentityKeyPair()
      const registrationId = keyhelper.generateRegistrationId()
      const storage = new FileSignalStorage(filePath, identityKeyPair, registrationId, options)
      storage.dirty = true
      storage.saveUnlocked()
      return storage
    } finally {
      if (lockToken !== undefined) {
        releaseFileLock(lockPath, lockToken)
      }
    }
  }

  private applySnapshot(data: PersistedState): void {
    this.nextPreKeyId = data.nextPreKeyId ?? 1
    this.latestSignedPreKey = data.latestSignedPreKey

    for (const [id, keyPair] of Object.entries(data.preKeys ?? {})) {
      this.preKeys.set(Number(id), keyPair)
    }

    for (const id of data.publishedPreKeyIds ?? []) {
      if (this.preKeys.has(id)) {
        this.publishedPreKeys.add(id)
      }
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
      try {
        this.sessions.set(id, SessionRecord.deserialize(buf))
      } catch (e) {
        throw new Error(`Invalid session record for "${id}": ${(e as Error).message}`)
      }
    }

    for (const [id, record] of Object.entries(data.senderKeys ?? {})) {
      try {
        this.senderKeys.set(id, SenderKeyRecord.deserialize(record))
      } catch (e) {
        throw new Error(`Invalid sender key record for "${id}": ${(e as Error).message}`)
      }
    }
  }

  private toSnapshot(revision: number): PersistedState {
    const sessions: Record<string, Buffer> = {}
    for (const [id, record] of this.sessions) {
      sessions[id] = record.serialize()
    }

    const senderKeys: Record<string, ReturnType<SenderKeyRecord["serialize"]>> = {}
    for (const [id, record] of this.senderKeys) {
      senderKeys[id] = record.serialize()
    }

    return {
      formatVersion: CURRENT_FORMAT_VERSION,
      revision,
      identityKeyPair: this.identityKeyPair,
      registrationId: this.registrationId,
      nextPreKeyId: this.nextPreKeyId,
      latestSignedPreKey: this.latestSignedPreKey,
      preKeys: Object.fromEntries(this.preKeys),
      publishedPreKeyIds: Array.from(this.publishedPreKeys).sort((a, b) => a - b),
      signedPreKeys: Object.fromEntries(this.signedPreKeys),
      retiredSignedPreKeys: Object.fromEntries(this.retiredSignedPreKeys),
      trustedIdentities: Object.fromEntries(this.trustedIdentities),
      sessions,
      senderKeys
    }
  }

  private withLock<T>(action: () => T): T {
    if (!this.lockEnabled) {
      return action()
    }

    const lockPath = `${this.filePath}.lock`
    const token = acquireFileLock(this.filePath, {
      lockTimeoutMs: this.lockTimeoutMs,
      staleLockMs: this.staleLockMs,
      fileMode: this.fileMode
    })
    try {
      return action()
    } finally {
      releaseFileLock(lockPath, token)
    }
  }

  private assertRevisionCurrent(encryptionKey: Buffer | undefined = this.encryptionKey): void {
    if (!fs.existsSync(this.filePath)) {
      if (this.revision === 0) {
        return
      }

      throw new FileSignalStorageConflictError(this.filePath, this.revision, 0, "file disappeared")
    }

    let current: LoadedState
    try {
      current = loadPersistedState(this.filePath, encryptionKey, false)
    } catch (e) {
      throw new FileSignalStorageConflictError(
        this.filePath,
        this.revision,
        -1,
        `cannot read the current revision: ${(e as Error).message}`
      )
    }

    if (current.data.revision !== this.revision) {
      throw new FileSignalStorageConflictError(this.filePath, this.revision, current.data.revision)
    }
  }

  private save(force = false, currentEncryptionKey: Buffer | undefined = this.encryptionKey): void {
    if (this.closed) {
      throw new Error("FileSignalStorage is closed")
    }

    if (!this.dirty && !force) {
      return
    }

    this.withLock(() => {
      this.assertRevisionCurrent(currentEncryptionKey)
      this.saveUnlocked()
    })
  }

  private saveUnlocked(): void {
    const nextRevision = this.revision + 1
    const json = JSON.stringify(this.toSnapshot(nextRevision))
    const payload = this.encryptionKey ? encryptPayload(json, this.encryptionKey) : json
    const tmpPath = `${this.filePath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`
    const backupPath = this.backupEnabled ? `${this.filePath}.bak` : undefined

    try {
      fs.writeFileSync(tmpPath, payload, { mode: this.fileMode })
      syncFile(tmpPath)

      if (backupPath && fs.existsSync(this.filePath)) {
        fs.rmSync(backupPath, { force: true })
        fs.renameSync(this.filePath, backupPath)
      }

      fs.renameSync(tmpPath, this.filePath)
      chmodFile(this.filePath, this.fileMode)
      syncDirectory(path.dirname(this.filePath))
      this.revision = nextRevision
      this.dirty = false
    } catch (e) {
      // Never leave a partially written temporary file behind.
      try {
        fs.rmSync(tmpPath, { force: true })
      } catch {
        // Ignore cleanup errors: the original save error is more useful.
      }

      // If the old snapshot was already moved aside, put it back so the next
      // open does not have to rely on backup recovery.
      if (backupPath && !fs.existsSync(this.filePath) && fs.existsSync(backupPath)) {
        try {
          fs.renameSync(backupPath, this.filePath)
        } catch {
          // Leave the backup in place; create() will recover from it.
        }
      }

      throw e
    }
  }

  private scheduleSave(): void {
    this.dirty = true
    if (this.closed) {
      return
    }

    if (this.saveTimer) {
      clearTimeout(this.saveTimer)
    }

    this.saveTimer = setTimeout(() => {
      this.saveTimer = undefined
      try {
        this.save()
      } catch (e) {
        this.handleSaveError(e)
      }
    }, this.saveDebounceMs)
  }

  private handleSaveError(e: unknown): void {
    const error = e instanceof Error ? e : new Error(String(e))
    try {
      this.onSaveError?.(error)
    } catch (callbackError) {
      getLogger().warn(`FileSignalStorage onSaveError callback failed: ${(callbackError as Error).message}`, {
        filePath: this.filePath
      })
    }

    getLogger().warn(`FileSignalStorage save failed: ${error.message}`, { filePath: this.filePath })
  }

  flush(): void {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer)
      this.saveTimer = undefined
    }

    if (!this.closed) {
      this.save()
    }
  }

  /**
   * Changes the key used for encryption at rest and writes the file again
   * immediately. Pass `undefined` to store the file as plain JSON again.
   */
  rotateEncryptionKey(encryptionKey?: Buffer): void {
    if (encryptionKey !== undefined && encryptionKey.byteLength !== ENCRYPTION_KEY_LENGTH) {
      throw new RangeError(`encryptionKey must be ${ENCRYPTION_KEY_LENGTH} bytes`)
    }

    if (this.closed) {
      throw new Error("FileSignalStorage is closed")
    }

    const previousEncryptionKey = this.encryptionKey
    this.encryptionKey = encryptionKey ? Buffer.from(encryptionKey) : undefined
    this.dirty = true
    try {
      this.save(true, previousEncryptionKey)
    } catch (e) {
      this.encryptionKey = previousEncryptionKey
      throw e
    }
  }

  /** Flushes pending writes. Alias kept for symmetry with other storage APIs. */
  close(): void {
    if (this.closed) {
      return
    }

    this.flush()
    this.closed = true
  }

  async loadSession(id: string): Promise<SessionRecord | undefined> {
    const stored = this.sessions.get(id)
    return stored ? SessionRecord.deserialize(stored.serialize()) : undefined
  }

  async storeSession(id: string, session: SessionRecord): Promise<void> {
    this.sessions.set(id, session)
    this.scheduleSave()
  }

  async loadSenderKey(senderKeyName: SenderKeyName): Promise<SenderKeyRecord | undefined> {
    const stored = this.senderKeys.get(senderKeyName.serialize())
    return stored ? SenderKeyRecord.deserialize(stored.serialize()) : undefined
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
      if (this.identityTrustPolicy === "strict") {
        return false
      }

      this.trustedIdentities.set(identifier, Buffer.from(identityKey))
      this.scheduleSave()
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

    this.scheduleSave()
    return changed
  }

  async removeIdentity(identifier: string): Promise<void> {
    this.trustedIdentities.delete(identifier)
    this.removeSessionsForIdentifier(identifier)
    this.scheduleSave()
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
    this.preKeys.delete(id)
    this.publishedPreKeys.delete(id)
    this.dirty = true
    this.save()
    this.emitPreKeyRemoved(id)
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
    this.dirty = true
    try {
      this.save()
      return true
    } catch (e) {
      this.publishedPreKeys.delete(id)
      throw e
    }
  }

  releasePreKey(id: number): boolean {
    if (!this.publishedPreKeys.delete(id)) {
      return false
    }

    this.dirty = true
    try {
      this.save()
      return true
    } catch (e) {
      this.publishedPreKeys.add(id)
      throw e
    }
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
    this.scheduleSave()
  }

  storeSignedPreKey(idOrRecord: number | SignedPreKey, keyPair?: KeyPair): void {
    if (typeof idOrRecord === "number") {
      this.signedPreKeys.set(idOrRecord, keyPair!)
      this.dirty = true
      this.save()
      return
    }

    if (this.latestSignedPreKey && this.latestSignedPreKey.keyId !== idOrRecord.keyId) {
      this.retiredSignedPreKeys.set(this.latestSignedPreKey.keyId, Date.now())
    }

    this.signedPreKeys.set(idOrRecord.keyId, idOrRecord.keyPair)
    this.latestSignedPreKey = idOrRecord
    this.pruneRetiredSignedPreKeys()
    this.dirty = true
    this.save()
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

  listPreKeyIds(): number[] {
    return Array.from(this.preKeys.keys()).sort((a, b) => a - b)
  }

  async getNextPreKeyId(): Promise<number> {
    return this.nextPreKeyId
  }

  async setNextPreKeyId(id: number): Promise<void> {
    this.nextPreKeyId = id
    this.dirty = true
    this.save()
  }

  async loadLatestSignedPreKey(): Promise<SignedPreKey | undefined> {
    return this.latestSignedPreKey
  }
}
