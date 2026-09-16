import type { KeyPair } from "./curve"
import * as keyhelper from "./keyhelper"
import type { PreKey, SignedPreKey } from "./keyhelper"
import { getLogger } from "./logger"

export interface PreKeyPoolStorage {
  storePreKey(id: number, keyPair: KeyPair): Promise<void> | void
  getPreKeyCount(): Promise<number> | number
  getNextPreKeyId(): Promise<number> | number
  setNextPreKeyId(id: number): Promise<void> | void
  storeSignedPreKey(record: SignedPreKey): Promise<void> | void
  loadLatestSignedPreKey(): Promise<SignedPreKey | undefined> | SignedPreKey | undefined
}

export interface PreKeyPoolOptions {
  minCount?: number
  replenishCount?: number
  concurrency?: number
  signedPreKeyMaxAgeMs?: number
}

export interface PreKeyPoolStatus {
  preKeyCount: number
  nextPreKeyId: number
  signedPreKeyId?: number
  signedPreKeyAgeMs?: number
}

const DEFAULT_MIN_COUNT = 20
const DEFAULT_REPLENISH_COUNT = 100

export class PreKeyPoolManager {
  private storage: PreKeyPoolStorage
  private identityKeyPair: KeyPair
  private minCount: number
  private replenishCount: number
  private concurrency: number | undefined
  private signedPreKeyMaxAgeMs: number
  private replenishing: Promise<PreKey[]> | undefined
  private rotatingSignedPreKey: Promise<SignedPreKey> | undefined

  constructor(storage: PreKeyPoolStorage, identityKeyPair: KeyPair, options: PreKeyPoolOptions = {}) {
    this.storage = storage
    this.identityKeyPair = identityKeyPair
    this.minCount = options.minCount ?? DEFAULT_MIN_COUNT
    this.replenishCount = options.replenishCount ?? DEFAULT_REPLENISH_COUNT
    this.concurrency = options.concurrency
    this.signedPreKeyMaxAgeMs = options.signedPreKeyMaxAgeMs ?? keyhelper.DEFAULT_SIGNED_PRE_KEY_MAX_AGE_MS
  }

  async ensurePreKeys(): Promise<void> {
    const count = await this.storage.getPreKeyCount()
    if (count >= this.minCount) {
      return
    }

    await this.replenishPreKeys()
  }

  async replenishPreKeys(count: number = this.replenishCount): Promise<PreKey[]> {
    if (this.replenishing) {
      return this.replenishing
    }

    this.replenishing = this._replenishPreKeys(count)
    try {
      return await this.replenishing
    } finally {
      this.replenishing = undefined
    }
  }

  private async _replenishPreKeys(count: number): Promise<PreKey[]> {
    const startId = await this.storage.getNextPreKeyId()
    const generated = await keyhelper.generatePreKeysBatch(startId, count, { concurrency: this.concurrency })

    for (const preKey of generated) {
      await this.storage.storePreKey(preKey.keyId, preKey.keyPair)
    }

    await this.storage.setNextPreKeyId(startId + count)
    getLogger().debug(`Replenished ${count} prekeys starting at id ${startId}`)
    return generated
  }

  async ensureSignedPreKey(): Promise<SignedPreKey> {
    const latest = await this.storage.loadLatestSignedPreKey()
    if (latest && !keyhelper.shouldRotateSignedPreKey(latest.createdAt, this.signedPreKeyMaxAgeMs)) {
      return latest
    }

    return this.rotateSignedPreKey(latest ? latest.keyId + 1 : 1)
  }

  async rotateSignedPreKey(keyId: number): Promise<SignedPreKey> {
    if (this.rotatingSignedPreKey) {
      return this.rotatingSignedPreKey
    }

    this.rotatingSignedPreKey = this._rotateSignedPreKey(keyId)
    try {
      return await this.rotatingSignedPreKey
    } finally {
      this.rotatingSignedPreKey = undefined
    }
  }

  private async _rotateSignedPreKey(keyId: number): Promise<SignedPreKey> {
    const signedPreKey = await keyhelper.generateSignedPreKeyAsync(this.identityKeyPair, keyId)
    await this.storage.storeSignedPreKey(signedPreKey)
    getLogger().debug(`Rotated signed prekey to id ${keyId}`)
    return signedPreKey
  }

  async getStatus(): Promise<PreKeyPoolStatus> {
    const [preKeyCount, nextPreKeyId, latestSignedPreKey] = await Promise.all([
      this.storage.getPreKeyCount(),
      this.storage.getNextPreKeyId(),
      this.storage.loadLatestSignedPreKey()
    ])

    return {
      preKeyCount,
      nextPreKeyId,
      signedPreKeyId: latestSignedPreKey?.keyId,
      signedPreKeyAgeMs: latestSignedPreKey ? Date.now() - latestSignedPreKey.createdAt : undefined
    }
  }
}
