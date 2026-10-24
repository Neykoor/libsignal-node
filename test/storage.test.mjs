import { after, describe, it } from "node:test"
import assert from "node:assert/strict"
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs"
import { hostname, tmpdir } from "node:os"
import { join } from "node:path"
import { randomBytes } from "node:crypto"
import {
  Direction,
  FileSignalStorage,
  FileSignalStorageConflictError,
  FileSignalStorageLockError,
  GroupSessionBuilder,
  MemorySignalStorage,
  PreKeyPoolManager,
  ProtocolAddress,
  SenderKeyDistributionMessage,
  SenderKeyName,
  SessionCipher,
  UntrustedIdentityKeyError,
  keyhelper
} from "../lib/index.js"
import { Party, createFileParty, createMemoryParty } from "./helpers.mjs"

const tempDirs = []
function tempFile(name = "session.json") {
  const dir = mkdtempSync(join(tmpdir(), "libsignal-test-"))
  tempDirs.push(dir)
  return join(dir, name)
}

async function waitFor(predicate, timeoutMs = 1000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) {
      return
    }

    await new Promise((resolve) => setTimeout(resolve, 5))
  }

  throw new Error("Timed out waiting for condition")
}

after(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true })
  }
})

describe("MemorySignalStorage", () => {
  it("returns defensive copies of sessions", async () => {
    const alice = createMemoryParty("alice")
    const bob = createMemoryParty("bob")
    bob.addSignedPreKey(1)
    bob.addPreKey(1)
    await alice.builderFor("bob").initOutgoing(bob.bundle())

    const first = await alice.storage.loadSession("bob.1")
    const second = await alice.storage.loadSession("bob.1")
    assert.ok(first && second)
    assert.notEqual(first, second)
    assert.deepEqual(first.serialize(), second.serialize())

    first.deleteAllSessions()
    const third = await alice.storage.loadSession("bob.1")
    assert.ok(third)
    assert.equal(third.haveOpenSession(), true)
  })

  it("removes sessions when an identity is removed or replaced", async () => {
    const alice = createMemoryParty("alice")
    const bob = createMemoryParty("bob")
    bob.addSignedPreKey(1)
    bob.addPreKey(1)
    await alice.builderFor("bob").initOutgoing(bob.bundle())

    await alice.storage.saveIdentity("bob", Buffer.alloc(33, 9))
    assert.equal(await alice.storage.loadSession("bob.1"), undefined)

    // Restore trust in Bob's real identity before establishing the session again.
    await alice.storage.saveIdentity("bob", bob.identity.pubKey)
    await alice.builderFor("bob").initOutgoing(bob.bundle())
    await alice.storage.removeIdentity("bob")
    assert.equal(await alice.storage.loadSession("bob.1"), undefined)
  })

  it("prunes retired signed prekeys after the grace period", async () => {
    const identity = keyhelper.generateIdentityKeyPair()
    const storage = new MemorySignalStorage(identity, 1, 0)
    const first = keyhelper.generateSignedPreKey(identity, 1)
    const second = keyhelper.generateSignedPreKey(identity, 2)

    storage.storeSignedPreKey(first)
    storage.storeSignedPreKey(second)
    assert.equal(await storage.loadSignedPreKey(1), undefined)
    assert.ok(await storage.loadSignedPreKey(2))
  })

  it("keeps retired signed prekeys during the grace period", async () => {
    const identity = keyhelper.generateIdentityKeyPair()
    const storage = new MemorySignalStorage(identity, 1)
    const first = keyhelper.generateSignedPreKey(identity, 1)
    const second = keyhelper.generateSignedPreKey(identity, 2)

    storage.storeSignedPreKey(first)
    storage.storeSignedPreKey(second)
    assert.ok(await storage.loadSignedPreKey(1))
    assert.ok(await storage.loadSignedPreKey(2))
  })

  it("removes all sender keys for a group", async () => {
    const party = createMemoryParty("alice")
    const first = new SenderKeyName("grupo", party.address())
    const second = new SenderKeyName("grupo", new ProtocolAddress("bob", 1))
    const unrelated = new SenderKeyName("otro", party.address())
    const builder = new GroupSessionBuilder(party.storage)

    await builder.create(first)
    await builder.create(second)
    await builder.create(unrelated)

    await party.storage.removeGroupSessions("grupo")
    assert.equal(await party.storage.loadSenderKey(first), undefined)
    assert.equal(await party.storage.loadSenderKey(second), undefined)
    assert.ok(await party.storage.loadSenderKey(unrelated))
  })

  it("rejects unknown identities in strict mode until they are saved explicitly", async () => {
    const identity = keyhelper.generateIdentityKeyPair()
    const storage = new MemorySignalStorage(identity, keyhelper.generateRegistrationId(), undefined, {
      identityTrustPolicy: "strict"
    })
    const remote = keyhelper.generateIdentityKeyPair()

    assert.equal(await storage.isTrustedIdentity("bob", remote.pubKey, Direction.SENDING), false)
    assert.equal(await storage.saveIdentity("bob", remote.pubKey), true)
    assert.equal(await storage.isTrustedIdentity("bob", remote.pubKey, Direction.SENDING), true)

    const otherIdentity = keyhelper.generateIdentityKeyPair()
    assert.equal(await storage.isTrustedIdentity("bob", otherIdentity.pubKey, Direction.SENDING), false)
  })

  it("strict mode blocks sessions until the remote identity is trusted", async () => {
    const identity = keyhelper.generateIdentityKeyPair()
    const registrationId = keyhelper.generateRegistrationId()
    const storage = new MemorySignalStorage(identity, registrationId, undefined, { identityTrustPolicy: "strict" })
    const alice = new Party("alice", storage, identity, registrationId)
    const bob = createMemoryParty("bob")
    bob.addSignedPreKey(1)
    bob.addPreKey(1)

    await assert.rejects(() => alice.builderFor("bob").initOutgoing(bob.bundle()), /Untrusted identity key/)

    await storage.saveIdentity("bob", bob.identity.pubKey)
    await alice.builderFor("bob").initOutgoing(bob.bundle())
    const message = await alice.cipherFor("bob").encrypt(Buffer.from("strict"))
    assert.deepEqual(await bob.cipherFor("alice").decryptPreKeyWhisperMessage(message.body), Buffer.from("strict"))
  })

  it("exposes stored identities and reports accepted identity changes", async () => {
    const identity = keyhelper.generateIdentityKeyPair()
    const events = []
    const storage = new MemorySignalStorage(identity, keyhelper.generateRegistrationId(), undefined, {
      onIdentityChanged: (event) => events.push(event)
    })
    const first = keyhelper.generateIdentityKeyPair()
    const second = keyhelper.generateIdentityKeyPair()

    assert.equal(await storage.isTrustedIdentity("bob", first.pubKey, Direction.SENDING), true)
    assert.deepEqual(storage.loadIdentity("bob"), first.pubKey)
    assert.deepEqual(storage.listIdentities(), ["bob"])

    const copy = storage.loadIdentity("bob")
    copy.fill(0)
    assert.deepEqual(storage.loadIdentity("bob"), first.pubKey)

    assert.equal(await storage.saveIdentity("bob", second.pubKey), true)
    assert.equal(events.length, 1)
    assert.equal(events[0].identifier, "bob")
    assert.deepEqual(events[0].identityKey, second.pubKey)
    assert.deepEqual(events[0].previousIdentityKey, first.pubKey)

    assert.equal(await storage.saveIdentity("bob", second.pubKey), false)
    assert.equal(events.length, 1)
  })

  it("includes the previous key when an identity mismatch is rejected", async () => {
    const alice = createMemoryParty("alice")
    const bob = createMemoryParty("bob")
    bob.addSignedPreKey(1)
    bob.addPreKey(1)
    await alice.builderFor("bob").initOutgoing(bob.bundle())

    const impostor = createMemoryParty("bob")
    impostor.addSignedPreKey(1)
    impostor.addPreKey(1)

    await assert.rejects(
      () => alice.builderFor("bob").initOutgoing(impostor.bundle()),
      (error) =>
        error instanceof UntrustedIdentityKeyError &&
        error.identityKey.equals(impostor.identity.pubKey) &&
        error.previousIdentityKey.equals(bob.identity.pubKey)
    )
  })
})

describe("FileSignalStorage", () => {
  it("persists identity, sessions and prekeys across reloads", async () => {
    const alicePath = tempFile("alice.json")
    const bobPath = tempFile("bob.json")
    const alice = await createFileParty("alice", alicePath)
    const bob = await createFileParty("bob", bobPath)
    bob.addSignedPreKey(1)
    bob.addPreKey(1)

    await alice.builderFor("bob").initOutgoing(bob.bundle())
    const aliceCipher = alice.cipherFor("bob")
    const bobCipher = bob.cipherFor("alice")

    const first = await aliceCipher.encrypt(Buffer.from("persistente"))
    assert.deepEqual(await bobCipher.decryptPreKeyWhisperMessage(first.body), Buffer.from("persistente"))
    const reply = await bobCipher.encrypt(Buffer.from("respuesta"))
    assert.deepEqual(await aliceCipher.decryptWhisperMessage(reply.body), Buffer.from("respuesta"))

    alice.storage.flush()
    bob.storage.flush()

    const aliceReloaded = await createFileParty("alice", alicePath)
    const bobReloaded = await createFileParty("bob", bobPath)
    assert.deepEqual(aliceReloaded.identity.pubKey, alice.identity.pubKey)
    assert.deepEqual(bobReloaded.identity.pubKey, bob.identity.pubKey)
    assert.equal(aliceReloaded.registrationId, alice.registrationId)
    assert.equal(bobReloaded.registrationId, bob.registrationId)
    assert.equal(await bobReloaded.storage.getPreKeyCount(), 0)

    const afterReload = await aliceReloaded.cipherFor("bob").encrypt(Buffer.from("tras reinicio"))
    assert.deepEqual(
      await bobReloaded.cipherFor("alice").decryptWhisperMessage(afterReload.body),
      Buffer.from("tras reinicio")
    )

    const responseAfterReload = await bobReloaded.cipherFor("alice").encrypt(Buffer.from("respuesta 2"))
    assert.deepEqual(
      await aliceReloaded.cipherFor("bob").decryptWhisperMessage(responseAfterReload.body),
      Buffer.from("respuesta 2")
    )
  })

  it("persists sender keys across reloads", async () => {
    const path = tempFile("sender.json")
    const alice = await createFileParty("alice", path)
    const name = new SenderKeyName("grupo", alice.address())
    const builder = new GroupSessionBuilder(alice.storage)

    const first = await builder.create(name)
    alice.storage.flush()

    const reloaded = await createFileParty("alice", path)
    const second = await new GroupSessionBuilder(reloaded.storage).create(name)
    const parsedFirst = new SenderKeyDistributionMessage(undefined, undefined, undefined, undefined, first.serialize())
    const parsedSecond = new SenderKeyDistributionMessage(undefined, undefined, undefined, undefined, second.serialize())
    assert.equal(parsedSecond.getId(), parsedFirst.getId())
    assert.equal(parsedSecond.getIteration(), parsedFirst.getIteration())
  })

  it("encrypts the whole file at rest", async () => {
    const path = tempFile("encrypted.json")
    const encryptionKey = randomBytes(32)
    const alice = await createFileParty("alice", path, { encryptionKey })
    alice.addPreKey(1)
    alice.storage.flush()

    const onDisk = JSON.parse(readFileSync(path, "utf-8"))
    assert.equal(onDisk.encrypted, true)
    assert.equal(typeof onDisk.data, "string")

    const reloaded = await createFileParty("alice", path, { encryptionKey })
    assert.equal(await reloaded.storage.getPreKeyCount(), 1)

    assert.throws(() => FileSignalStorage.create(path), /encryptionKey is required/)
    assert.throws(() => FileSignalStorage.create(path, { encryptionKey: randomBytes(32) }), /Failed to decrypt/)
  })

  it("rejects encryption keys of the wrong length", () => {
    assert.throws(
      () => FileSignalStorage.create(tempFile(), { encryptionKey: randomBytes(16) }),
      /encryptionKey must be 32 bytes/
    )
  })

  it("creates parent directories and writes atomically", async () => {
    const dir = mkdtempSync(join(tmpdir(), "libsignal-test-"))
    tempDirs.push(dir)
    const path = join(dir, "nested", "deep", "session.json")
    const alice = await createFileParty("alice", path)
    assert.ok(alice.identity.pubKey.length === 33)
  })

  it("writes a format version and loads legacy unversioned files", async () => {
    const path = tempFile("version.json")
    const storage = FileSignalStorage.create(path)
    await storage.setNextPreKeyId(7)
    storage.flush()

    const raw = JSON.parse(readFileSync(path, "utf-8"))
    assert.equal(raw.formatVersion, 1)

    delete raw.formatVersion
    writeFileSync(path, JSON.stringify(raw))

    const legacy = FileSignalStorage.create(path)
    assert.equal(await legacy.getNextPreKeyId(), 7)
    legacy.flush()
    assert.equal(JSON.parse(readFileSync(path, "utf-8")).formatVersion, 1)
  })

  it("rejects unsupported versions and corrupted snapshots with clear errors", () => {
    const path = tempFile("invalid.json")
    const storage = FileSignalStorage.create(path)
    storage.flush()

    const raw = JSON.parse(readFileSync(path, "utf-8"))
    raw.formatVersion = 999
    writeFileSync(path, JSON.stringify(raw))
    assert.throws(() => FileSignalStorage.create(path), /unsupported formatVersion 999/)

    raw.formatVersion = 1
    raw.identityKeyPair.privKey = { type: "Buffer", data: [1, 2, 3] }
    writeFileSync(path, JSON.stringify(raw))
    assert.throws(() => FileSignalStorage.create(path), /identityKeyPair\.privKey must be 32 bytes/)
  })

  it("rejects a corrupted stored session with a clear error", () => {
    const path = tempFile("corrupt-session.json")
    const storage = FileSignalStorage.create(path)
    storage.flush()

    const raw = JSON.parse(readFileSync(path, "utf-8"))
    raw.sessions["bob.1"] = { type: "Buffer", data: Array.from(Buffer.from("not json")) }
    writeFileSync(path, JSON.stringify(raw))
    assert.throws(() => FileSignalStorage.create(path), /Invalid session record for "bob\.1"/)
  })

  it("rotates the encryption key at rest", async () => {
    const path = tempFile("rotate.json")
    const storage = FileSignalStorage.create(path)
    await storage.setNextPreKeyId(42)
    storage.flush()

    const key = randomBytes(32)
    storage.rotateEncryptionKey(key)
    assert.equal(JSON.parse(readFileSync(path, "utf-8")).encrypted, true)

    const encrypted = FileSignalStorage.create(path, { encryptionKey: key })
    assert.equal(await encrypted.getNextPreKeyId(), 42)

    encrypted.rotateEncryptionKey(undefined)
    const plain = JSON.parse(readFileSync(path, "utf-8"))
    assert.equal(plain.encrypted, undefined)
    assert.equal(plain.formatVersion, 1)

    const reloaded = FileSignalStorage.create(path)
    assert.equal(await reloaded.getNextPreKeyId(), 42)
    assert.throws(() => reloaded.rotateEncryptionKey(randomBytes(16)), /encryptionKey must be 32 bytes/)
  })

  it("supports strict identity trust in files", async () => {
    const path = tempFile("strict.json")
    const storage = FileSignalStorage.create(path, { identityTrustPolicy: "strict" })
    const remote = keyhelper.generateIdentityKeyPair()

    assert.equal(await storage.isTrustedIdentity("bob", remote.pubKey, Direction.RECEIVING), false)
    await storage.saveIdentity("bob", remote.pubKey)
    assert.equal(await storage.isTrustedIdentity("bob", remote.pubKey, Direction.RECEIVING), true)
    assert.deepEqual(storage.loadIdentity("bob"), remote.pubKey)
    assert.deepEqual(storage.listIdentities(), ["bob"])

    storage.flush()
    const reloaded = FileSignalStorage.create(path, { identityTrustPolicy: "strict" })
    assert.equal(await reloaded.isTrustedIdentity("bob", remote.pubKey, Direction.RECEIVING), true)
    assert.deepEqual(reloaded.loadIdentity("bob"), remote.pubKey)
    reloaded.close()
  })

  it("reports accepted identity changes in files", async () => {
    const path = tempFile("identity-change.json")
    const events = []
    const storage = FileSignalStorage.create(path, {
      onIdentityChanged: (event) => events.push(event)
    })
    const first = keyhelper.generateIdentityKeyPair()
    const second = keyhelper.generateIdentityKeyPair()

    await storage.saveIdentity("bob", first.pubKey)
    await storage.saveIdentity("bob", second.pubKey)
    assert.equal(events.length, 1)
    assert.deepEqual(events[0].previousIdentityKey, first.pubKey)
    assert.deepEqual(events[0].identityKey, second.pubKey)
    storage.close()

    const reloaded = FileSignalStorage.create(path)
    assert.deepEqual(reloaded.loadIdentity("bob"), second.pubKey)
    assert.deepEqual(reloaded.listIdentities(), ["bob"])
    reloaded.close()
  })

  it("leaves no temporary files behind", () => {
    const dir = mkdtempSync(join(tmpdir(), "libsignal-test-"))
    tempDirs.push(dir)
    const path = join(dir, "session.json")
    const storage = FileSignalStorage.create(path)
    storage.flush()
    storage.close()

    assert.deepEqual(readdirSync(dir), ["session.json"])
  })

  it("removes stale temporary files left by a crash", () => {
    const dir = mkdtempSync(join(tmpdir(), "libsignal-test-"))
    tempDirs.push(dir)
    const path = join(dir, "stale.json")
    const stalePath = `${path}.12345.abcdefabcdef.tmp`
    writeFileSync(stalePath, "partial")

    const storage = FileSignalStorage.create(path)
    storage.close()
    assert.equal(existsSync(stalePath), false)
    assert.deepEqual(readdirSync(dir), ["stale.json"])
  })

  it("can disable backups", async () => {
    const path = tempFile("no-backup.json")
    const storage = FileSignalStorage.create(path, { backup: false })
    await storage.setNextPreKeyId(7)
    storage.close()
    assert.equal(existsSync(`${path}.bak`), false)
  })

  it("keeps a backup and recovers from a corrupted snapshot", async () => {
    const dir = mkdtempSync(join(tmpdir(), "libsignal-test-"))
    tempDirs.push(dir)
    const path = join(dir, "backup.json")
    const storage = FileSignalStorage.create(path)

    await storage.setNextPreKeyId(7)
    await storage.setNextPreKeyId(8)
    storage.close()
    assert.ok(existsSync(`${path}.bak`))

    writeFileSync(path, "{ this is not valid json")
    const recovered = FileSignalStorage.create(path)
    assert.equal(await recovered.getNextPreKeyId(), 7)
    assert.ok(readdirSync(dir).some((name) => name.startsWith("backup.json.corrupt-")))
    recovered.close()
  })

  it("detects concurrent writers instead of silently overwriting them", async () => {
    const path = tempFile("conflict.json")
    const first = FileSignalStorage.create(path)
    const second = FileSignalStorage.create(path)

    await first.setNextPreKeyId(7)
    await assert.rejects(
      () => second.setNextPreKeyId(8),
      (error) => error instanceof FileSignalStorageConflictError
    )

    const reloaded = FileSignalStorage.create(path)
    assert.equal(await reloaded.getNextPreKeyId(), 7)
    first.close()
    reloaded.close()
    assert.throws(() => second.close(), (error) => error instanceof FileSignalStorageConflictError)
  })

  it("uses a lock file and rejects an active owner", () => {
    const path = tempFile("locked.json")
    const lockPath = `${path}.lock`
    writeFileSync(
      lockPath,
      JSON.stringify({
        token: "test",
        pid: process.pid,
        hostname: hostname(),
        createdAt: Date.now(),
        filePath: path
      })
    )

    assert.throws(
      () => FileSignalStorage.create(path, { lockTimeoutMs: 0 }),
      (error) => error instanceof FileSignalStorageLockError
    )

    rmSync(lockPath, { force: true })
    const storage = FileSignalStorage.create(path, { lockTimeoutMs: 0 })
    assert.equal(existsSync(lockPath), false)
    storage.close()
  })

  it("removes a lock left by a process that no longer exists", () => {
    const path = tempFile("stale-lock.json")
    const lockPath = `${path}.lock`
    writeFileSync(
      lockPath,
      JSON.stringify({
        token: "stale",
        pid: 0,
        hostname: hostname(),
        createdAt: Date.now(),
        filePath: path
      })
    )

    const storage = FileSignalStorage.create(path, { lockTimeoutMs: 0 })
    assert.equal(existsSync(lockPath), false)
    storage.close()
  })

  it("reports debounced save conflicts through onSaveError", async () => {
    const path = tempFile("save-error.json")
    const first = FileSignalStorage.create(path)
    let saveError
    const second = FileSignalStorage.create(path, {
      saveDebounceMs: 5,
      onSaveError: (error) => {
        saveError = error
      }
    })

    second.storePreKey(1, keyhelper.generatePreKey(1).keyPair)
    await first.setNextPreKeyId(7)
    await waitFor(() => saveError instanceof FileSignalStorageConflictError)

    first.close()
    assert.throws(() => second.close(), (error) => error instanceof FileSignalStorageConflictError)
  })
})

describe("PreKeyPoolManager", () => {
  function createPool(options = {}) {
    const identity = keyhelper.generateIdentityKeyPair()
    const storage = new MemorySignalStorage(identity, keyhelper.generateRegistrationId())
    return {
      identity,
      storage,
      pool: new PreKeyPoolManager(storage, identity, { minCount: 2, replenishCount: 5, ...options })
    }
  }

  it("replenishes prekeys only when below the minimum", async () => {
    const { storage, pool } = createPool()
    await pool.ensurePreKeys()
    assert.equal(await storage.getPreKeyCount(), 5)
    assert.equal(await storage.getNextPreKeyId(), 6)

    await pool.ensurePreKeys()
    assert.equal(await storage.getPreKeyCount(), 5)

    const extra = await pool.replenishPreKeys(3)
    assert.equal(extra.length, 3)
    assert.equal(await storage.getPreKeyCount(), 8)
    assert.equal(await storage.getNextPreKeyId(), 9)
  })

  it("creates and rotates signed prekeys", async () => {
    const { storage, pool } = createPool({ signedPreKeyMaxAgeMs: 0 })
    await pool.ensurePreKeys()
    const first = await pool.ensureSignedPreKey()
    assert.equal(first.keyId, 1)
    assert.ok((await storage.loadSignedPreKey(1))?.privKey)

    const second = await pool.ensureSignedPreKey()
    assert.equal(second.keyId, 2)
    assert.ok(await storage.loadSignedPreKey(2))

    const status = await pool.getStatus()
    assert.equal(status.preKeyCount, 5)
    assert.equal(status.signedPreKeyId, 2)
    assert.ok(typeof status.signedPreKeyAgeMs === "number")
  })

  it("creates a valid bundle whose prekey is consumed by a session", async () => {
    const { identity, storage, pool } = createPool()
    const bundle = await pool.createBundle()

    assert.equal(bundle.registrationId, await storage.getOurRegistrationId())
    assert.deepEqual(bundle.identityKey, identity.pubKey)
    assert.equal(bundle.preKey?.keyId, 1)
    assert.equal(bundle.preKey?.publicKey.length, 33)
    assert.equal(bundle.signedPreKey.signature.length, 64)
    assert.equal(await storage.getPreKeyCount(), 5)

    const remote = createMemoryParty("remote")
    await remote.builderFor("pool").initOutgoing(bundle)
    const message = await remote.cipherFor("pool").encrypt(Buffer.from("desde el bundle"))

    const receiver = new SessionCipher(storage, new ProtocolAddress("remote", 1))
    assert.deepEqual(await receiver.decryptPreKeyWhisperMessage(message.body), Buffer.from("desde el bundle"))
    assert.equal(await storage.getPreKeyCount(), 4)

    await assert.rejects(() => pool.createBundle({ preKeyId: 999 }), /No prekey found with id 999/)

    const originalIdentityKey = Buffer.from(identity.pubKey)
    bundle.identityKey.fill(0)
    assert.deepEqual(identity.pubKey, originalIdentityKey)
  })

  it("reserves a different prekey for every bundle and can release it", async () => {
    const { storage, pool } = createPool()
    const first = await pool.createBundle()
    const second = await pool.createBundle()

    assert.equal(first.preKey?.keyId, 1)
    assert.equal(second.preKey?.keyId, 2)
    assert.deepEqual(storage.listAvailablePreKeyIds(), [3, 4, 5])

    const status = await pool.getStatus()
    assert.equal(status.availablePreKeyCount, 3)
    assert.equal(status.publishedPreKeyCount, 2)

    await assert.rejects(
      () => pool.createBundle({ preKeyId: first.preKey.keyId }),
      /has already been published/
    )

    assert.equal(await pool.releasePreKey(first.preKey.keyId), true)
    const reused = await pool.createBundle()
    assert.equal(reused.preKey?.keyId, first.preKey.keyId)
  })

  it("replenishes consumed prekeys while automatic maintenance is active", async () => {
    const { storage, pool } = createPool({ minCount: 10, replenishCount: 5 })
    const stop = pool.startAutoMaintenance(60_000)
    try {
      await waitFor(async () => (await storage.getPreKeyCount()) === 5)
      await storage.removePreKey(1)
      await waitFor(async () => (await storage.getPreKeyCount()) === 9)
    } finally {
      stop()
    }
  })

  it("persists published prekeys across FileSignalStorage reloads", async () => {
    const path = tempFile("published.json")
    const storage = FileSignalStorage.create(path)
    const identity = await storage.getOurIdentity()
    const pool = new PreKeyPoolManager(storage, identity, { minCount: 2, replenishCount: 3 })

    const first = await pool.createBundle()
    assert.equal(first.preKey?.keyId, 1)
    storage.close()

    const reloaded = FileSignalStorage.create(path)
    const reloadedIdentity = await reloaded.getOurIdentity()
    const reloadedPool = new PreKeyPoolManager(reloaded, reloadedIdentity, { minCount: 2, replenishCount: 3 })
    const second = await reloadedPool.createBundle()
    assert.equal(second.preKey?.keyId, 2)
    reloaded.close()
  })

  it("creates a bundle from an explicit prekey id without listPreKeyIds()", async () => {
    const { identity, storage } = createPool()
    storage.storePreKey(7, keyhelper.generatePreKey(7).keyPair)

    const minimalStorage = {
      getPreKeyCount: () => storage.getPreKeyCount(),
      getNextPreKeyId: () => storage.getNextPreKeyId(),
      setNextPreKeyId: (id) => storage.setNextPreKeyId(id),
      storePreKey: (id, keyPair) => storage.storePreKey(id, keyPair),
      storeSignedPreKey: (record) => storage.storeSignedPreKey(record),
      loadLatestSignedPreKey: () => storage.loadLatestSignedPreKey(),
      loadPreKey: (id) => storage.loadPreKey(id),
      getOurRegistrationId: () => storage.getOurRegistrationId()
    }

    const pool = new PreKeyPoolManager(minimalStorage, identity, { minCount: 0, replenishCount: 1 })
    const bundle = await pool.createBundle({ preKeyId: 7 })
    assert.equal(bundle.preKey?.keyId, 7)
  })

  it("reserves prekey ids before storing keys so a failure cannot reuse them", async () => {
    const identity = keyhelper.generateIdentityKeyPair()
    const inner = new MemorySignalStorage(identity, keyhelper.generateRegistrationId())
    let fail = true

    const storage = {
      storePreKey(id, keyPair) {
        if (fail) {
          throw new Error("simulated disk failure")
        }

        return inner.storePreKey(id, keyPair)
      },
      getPreKeyCount: () => inner.getPreKeyCount(),
      getNextPreKeyId: () => inner.getNextPreKeyId(),
      setNextPreKeyId: (id) => inner.setNextPreKeyId(id),
      storeSignedPreKey: (record) => inner.storeSignedPreKey(record),
      loadLatestSignedPreKey: () => inner.loadLatestSignedPreKey(),
      loadPreKey: (id) => inner.loadPreKey(id),
      listPreKeyIds: () => inner.listPreKeyIds(),
      getOurRegistrationId: () => inner.getOurRegistrationId()
    }

    const pool = new PreKeyPoolManager(storage, identity, { minCount: 2, replenishCount: 5 })
    await assert.rejects(() => pool.replenishPreKeys(), /simulated disk failure/)
    assert.equal(await inner.getNextPreKeyId(), 6)
    assert.deepEqual(inner.listPreKeyIds(), [])

    fail = false
    await pool.replenishPreKeys()
    assert.deepEqual(inner.listPreKeyIds(), [6, 7, 8, 9, 10])
    assert.equal(await inner.getNextPreKeyId(), 11)
  })

  it("runs automatic maintenance and can be stopped", async () => {
    const { storage, pool } = createPool({ signedPreKeyMaxAgeMs: 60_000 })
    const stop = pool.startAutoMaintenance(60_000)
    await new Promise((resolve) => setTimeout(resolve, 50))
    stop()

    assert.equal(await storage.getPreKeyCount(), 5)
    assert.ok(await storage.loadLatestSignedPreKey())
  })
})
