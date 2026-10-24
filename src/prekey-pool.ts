import type { KeyPair } from "./curve"
import * as keyhelper from "./keyhelper"
import type { PreKey, SignedPreKey } from "./keyhelper"
import { getLogger } from "./logger"
import { assertValidDeviceKeyBundle } from "./prekey-bundle-validator"
import type { DeviceKeyBundle } from "./types"

export interface PreKeyPoolStorage {
  storePreKey(id: number, keyPair: KeyPair): Promise<void> | void
  getPreKeyCount(): Promise<number> | number
  getNextPreKeyId(): Promise<number> | number
  setNextPreKeyId(id: number): Promise<void> | void
  storeSignedPreKey(record: SignedPreKey): Promise<void> | void
  loadLatestSignedPreKey(): Promise<SignedPreKey | undefined> | SignedPreKey | undefined
  /** Optional helpers used by `createBundle()`. */
  loadPreKey?(id: number): Promise<KeyPair | undefined> | KeyPair | undefined
  listPreKeyIds?(): Promise<number[]> | number[]
  getOurRegistrationId?(): Promise<number> | number
  /**
   * Number of prekeys that have never been included in a bundle. Storages that
   * do not track published prekeys can omit this; the total count is used.
   */
  getAvailablePreKeyCount?(): Promise<number> | number
  /** Prekeys that have not been reserved for a bundle yet. */
  listAvailablePreKeyIds?(): Promise<number[]> | number[]
  /**
   * Atomically marks a prekey as published so it is not returned by another
   * `createBundle()` call. Returns false when the id does not exist or was
   * already published.
   */
  reservePreKey?(id: number): Promise<boolean> | boolean
  /** Releases a published prekey that was never used. */
  releasePreKey?(id: number): Promise<boolean> | boolean
  /** Registers a listener invoked after a prekey is consumed. */
  onPreKeyRemoved?(listener: (id: number) => void): () => void
}

export interface PreKeyPoolOptions {
  minCount?: number
  replenishCount?: number
  concurrency?: number
  signedPreKeyMaxAgeMs?: number
}

export interface PreKeyPoolStatus {
  preKeyCount: number
  availablePreKeyCount?: number
  publishedPreKeyCount?: number
  nextPreKeyId: number
  signedPreKeyId?: number
  signedPreKeyAgeMs?: number
}

export interface CreatePreKeyBundleOptions {
  /** Defaults to the registration id exposed by the storage, when available. */
  registrationId?: number
  /** Defaults to the lowest prekey id currently available for publication. */
  preKeyId?: number
  /**
   * Marks the selected prekey as published so another bundle does not reuse
   * it. Defaults to true when the storage supports reservations.
   */
  reserve?: boolean
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
    const count = this.storage.getAvailablePreKeyCount
      ? await this.storage.getAvailablePreKeyCount()
      : await this.storage.getPreKeyCount()
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

    // Reserve the whole range before writing any key. If the process crashes
    // halfway through, the next replenishment skips the range instead of
    // reusing and overwriting ids that may already have been published.
    await this.storage.setNextPreKeyId(keyhelper.wrapPreKeyId(startId + count))

    const generated = await keyhelper.generatePreKeysBatch(startId, count, { concurrency: this.concurrency })

    for (const preKey of generated) {
      await this.storage.storePreKey(preKey.keyId, preKey.keyPair)
    }

    getLogger().debug(`Replenished ${count} prekeys starting at id ${startId}`)
    return generated
  }

  /**
   * Builds a publishable `DeviceKeyBundle` from the current pool.
   *
   * By default the selected prekey is reserved so a second bundle cannot
   * publish the same one-time prekey. The private key remains available for
   * decryption until an incoming `PreKeyWhisperMessage` consumes it.
   */
  async createBundle(options: CreatePreKeyBundleOptions = {}): Promise<DeviceKeyBundle> {
    await this.ensurePreKeys()

    if (!this.storage.loadPreKey) {
      throw new Error("PreKeyPoolStorage must implement loadPreKey() to create bundles")
    }

    const signedPreKey = await this.ensureSignedPreKey()
    const registrationId = options.registrationId ?? (await this.storage.getOurRegistrationId?.())
    if (registrationId === undefined) {
      throw new Error("registrationId is required to create a bundle")
    }

    const reserve = options.reserve !== false && !!this.storage.reservePreKey
    if (options.preKeyId !== undefined) {
      const bundle = await this.buildBundle(options.preKeyId, signedPreKey, registrationId)
      if (reserve && !(await this.storage.reservePreKey!(options.preKeyId))) {
        throw new Error(`Prekey ${options.preKeyId} has already been published`)
      }

      return bundle
    }

    const attempted = new Set<number>()
    for (let round = 0; round < 2; round++) {
      const preKeyIds = await this.listCandidatePreKeyIds(reserve)
      for (const preKeyId of preKeyIds) {
        if (attempted.has(preKeyId)) {
          continue
        }

        attempted.add(preKeyId)
        const bundle = await this.buildBundle(preKeyId, signedPreKey, registrationId)

        if (!reserve || (await this.storage.reservePreKey!(preKeyId))) {
          return bundle
        }

        // Another caller reserved this id while we were building the bundle.
        // Continue with the next available id.
      }

      if (round === 0) {
        await this.replenishPreKeys()
      }
    }

    throw new Error("No available prekeys to create a bundle; replenish the pool or release unused prekeys")
  }

  private async buildBundle(
    preKeyId: number,
    signedPreKey: SignedPreKey,
    registrationId: number
  ): Promise<DeviceKeyBundle> {
    const preKeyPair = await this.storage.loadPreKey!(preKeyId)
    if (!preKeyPair) {
      throw new Error(`No prekey found with id ${preKeyId}`)
    }

    const bundle: DeviceKeyBundle = {
      registrationId,
      identityKey: Buffer.from(this.identityKeyPair.pubKey),
      signedPreKey: {
        keyId: signedPreKey.keyId,
        publicKey: Buffer.from(signedPreKey.keyPair.pubKey),
        signature: Buffer.from(signedPreKey.signature)
      },
      preKey: {
        keyId: preKeyId,
        publicKey: Buffer.from(preKeyPair.pubKey)
      }
    }

    assertValidDeviceKeyBundle(bundle)
    return bundle
  }

  private async listCandidatePreKeyIds(availableOnly: boolean): Promise<number[]> {
    let preKeyIds: number[] | undefined
    if (availableOnly && this.storage.listAvailablePreKeyIds) {
      preKeyIds = await this.storage.listAvailablePreKeyIds()
    } else if (this.storage.listPreKeyIds) {
      preKeyIds = await this.storage.listPreKeyIds()
    }

    if (!preKeyIds) {
      throw new Error(
        "No prekeys available to create a bundle; provide preKeyId or implement listPreKeyIds()/listAvailablePreKeyIds()"
      )
    }

    return preKeyIds.slice().sort((a, b) => a - b)
  }

  /**
   * Releases a prekey reserved by `createBundle()` when the bundle was never
   * published or will not be used.
   */
  async releasePreKey(id: number): Promise<boolean> {
    if (!this.storage.releasePreKey) {
      throw new Error("PreKeyPoolStorage must implement releasePreKey() to release published prekeys")
    }

    return await this.storage.releasePreKey(id)
  }

  async ensureSignedPreKey(): Promise<SignedPreKey> {
    const latest = await this.storage.loadLatestSignedPreKey()
    if (latest && !keyhelper.shouldRotateSignedPreKey(latest.createdAt, this.signedPreKeyMaxAgeMs)) {
      return latest
    }

    return this.rotateSignedPreKey(latest ? keyhelper.wrapPreKeyId(latest.keyId + 1) : 1)
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
    const [preKeyCount, availablePreKeyCount, nextPreKeyId, latestSignedPreKey] = await Promise.all([
      this.storage.getPreKeyCount(),
      this.storage.getAvailablePreKeyCount ? this.storage.getAvailablePreKeyCount() : Promise.resolve(undefined),
      this.storage.getNextPreKeyId(),
      this.storage.loadLatestSignedPreKey()
    ])

    return {
      preKeyCount,
      availablePreKeyCount,
      publishedPreKeyCount:
        availablePreKeyCount === undefined ? undefined : Math.max(0, preKeyCount - availablePreKeyCount),
      nextPreKeyId,
      signedPreKeyId: latestSignedPreKey?.keyId,
      signedPreKeyAgeMs: latestSignedPreKey ? Date.now() - latestSignedPreKey.createdAt : undefined
    }
  }

  startAutoMaintenance(intervalMs: number = 60 * 60 * 1000): () => void {
    const run = (): void => {
      this.ensurePreKeys().catch(err => getLogger().warn("Failed to ensure prekeys", err))
      this.ensureSignedPreKey().catch(err => getLogger().warn("Failed to ensure signed prekey", err))
    }

    run()
    const timer = setInterval(run, intervalMs)
    timer.unref()
    const unsubscribe = this.storage.onPreKeyRemoved?.(() => {
      this.ensurePreKeys().catch(err => getLogger().warn("Failed to replenish consumed prekey", err))
    })

    return () => {
      clearInterval(timer)
      unsubscribe?.()
    }
  }
}
