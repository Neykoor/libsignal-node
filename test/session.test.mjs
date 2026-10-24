import { describe, it } from "node:test"
import assert from "node:assert/strict"
import {
  assertValidIncomingPreKeyMessage,
  MessageCounterError,
  PreKeyError,
  SessionRecord,
  protobufs
} from "../lib/index.js"
import { createMemoryParty, createMemoryPartyWithIdentity, establishSession, flipByte } from "./helpers.mjs"

async function makePair() {
  const alice = createMemoryParty("alice")
  const bob = createMemoryParty("bob")
  bob.addSignedPreKey(1)
  bob.addPreKey(1)
  const { senderCipher, recipientCipher } = await establishSession(alice, bob)
  return { alice, bob, aliceCipher: senderCipher, bobCipher: recipientCipher }
}

describe("Signal Protocol sessions", () => {
  it("establishes an outgoing session and decrypts the first prekey message", async () => {
    const alice = createMemoryParty("alice")
    const bob = createMemoryParty("bob")
    bob.addSignedPreKey(1)
    bob.addPreKey(1)

    await alice.builderFor("bob").initOutgoing(bob.bundle())
    const aliceCipher = alice.cipherFor("bob")
    const bobCipher = bob.cipherFor("alice")

    const message = await aliceCipher.encrypt(Buffer.from("hola bob"))
    assert.equal(message.type, 3)
    assert.equal(message.registrationId, bob.registrationId)

    const plaintext = await bobCipher.decryptPreKeyWhisperMessage(message.body)
    assert.deepEqual(plaintext, Buffer.from("hola bob"))

    // The one-time prekey must be consumed after a successful decryption.
    assert.equal(await bob.storage.getPreKeyCount(), 0)

    const reply = await bobCipher.encrypt(Buffer.from("hola alice"))
    assert.equal(reply.type, 1)
    assert.deepEqual(await aliceCipher.decryptWhisperMessage(reply.body), Buffer.from("hola alice"))
  })

  it("works without a one-time prekey", async () => {
    const alice = createMemoryParty("alice")
    const bob = createMemoryParty("bob")
    bob.addSignedPreKey(4)

    await alice.builderFor("bob").initOutgoing(bob.bundle({ signedPreKeyId: 4 }))
    const aliceCipher = alice.cipherFor("bob")
    const bobCipher = bob.cipherFor("alice")

    const message = await aliceCipher.encrypt(Buffer.from("sin prekey"))
    const plaintext = await bobCipher.decryptPreKeyWhisperMessage(message.body)
    assert.deepEqual(plaintext, Buffer.from("sin prekey"))
  })

  it("supports several messages in both directions", async () => {
    const { aliceCipher, bobCipher } = await makePair()

    const first = await aliceCipher.encrypt(Buffer.from("m1"))
    assert.deepEqual(await bobCipher.decryptPreKeyWhisperMessage(first.body), Buffer.from("m1"))

    for (let i = 0; i < 5; i++) {
      const fromBob = await bobCipher.encrypt(Buffer.from(`b${i}`))
      assert.deepEqual(await aliceCipher.decryptWhisperMessage(fromBob.body), Buffer.from(`b${i}`))

      const fromAlice = await aliceCipher.encrypt(Buffer.from(`a${i}`))
      assert.deepEqual(await bobCipher.decryptWhisperMessage(fromAlice.body), Buffer.from(`a${i}`))
    }
  })

  it("decrypts out-of-order messages and caches skipped keys", async () => {
    const { aliceCipher, bobCipher } = await makePair()

    // Establish the session and receive one reply, so Alice stops wrapping
    // messages in PreKeyWhisperMessage envelopes.
    const hello = await aliceCipher.encrypt(Buffer.from("hola"))
    assert.deepEqual(await bobCipher.decryptPreKeyWhisperMessage(hello.body), Buffer.from("hola"))
    const reply = await bobCipher.encrypt(Buffer.from("reply"))
    assert.deepEqual(await aliceCipher.decryptWhisperMessage(reply.body), Buffer.from("reply"))

    const m1 = await aliceCipher.encrypt(Buffer.from("uno"))
    const m2 = await aliceCipher.encrypt(Buffer.from("dos"))
    const m3 = await aliceCipher.encrypt(Buffer.from("tres"))
    assert.equal(m1.type, 1)
    assert.equal(m2.type, 1)
    assert.equal(m3.type, 1)

    assert.deepEqual(await bobCipher.decryptWhisperMessage(m3.body), Buffer.from("tres"))
    assert.deepEqual(await bobCipher.decryptWhisperMessage(m1.body), Buffer.from("uno"))
    assert.deepEqual(await bobCipher.decryptWhisperMessage(m2.body), Buffer.from("dos"))
  })

  it("rejects replayed messages", async () => {
    const { aliceCipher, bobCipher } = await makePair()
    const message = await aliceCipher.encrypt(Buffer.from("una vez"))

    assert.deepEqual(await bobCipher.decryptPreKeyWhisperMessage(message.body), Buffer.from("una vez"))
    await assert.rejects(
      () => bobCipher.decryptPreKeyWhisperMessage(message.body),
      (error) => error instanceof MessageCounterError || error instanceof PreKeyError
    )
  })

  it("rejects tampered ciphertext without breaking the session", async () => {
    const { aliceCipher, bobCipher } = await makePair()
    const first = await aliceCipher.encrypt(Buffer.from("valido"))
    await bobCipher.decryptPreKeyWhisperMessage(first.body)
    const reply = await bobCipher.encrypt(Buffer.from("reply"))
    await aliceCipher.decryptWhisperMessage(reply.body)

    const second = await aliceCipher.encrypt(Buffer.from("integro"))
    // Last byte of the protobuf-encoded ciphertext, before the 8-byte MAC.
    const tampered = flipByte(second.body, second.body.length - 9)
    await assert.rejects(
      () => bobCipher.decryptWhisperMessage(tampered),
      (error) => (error.errors ?? [error]).some((inner) => /Bad MAC/.test(inner.message))
    )

    assert.deepEqual(await bobCipher.decryptWhisperMessage(second.body), Buffer.from("integro"))
  })

  it("rejects messages for the wrong session/recipient", async () => {
    const { aliceCipher } = await makePair()
    const charlie = createMemoryParty("charlie")
    charlie.addSignedPreKey(1)
    charlie.addPreKey(1)
    const charlieCipher = charlie.cipherFor("alice")

    const message = await aliceCipher.encrypt(Buffer.from("privado"))
    await assert.rejects(() => charlieCipher.decryptPreKeyWhisperMessage(message.body))
  })

  it("rejects invalid prekey message versions and truncated data", async () => {
    const bob = createMemoryParty("bob")
    const bobCipher = bob.cipherFor("alice")

    await assert.rejects(() => bobCipher.decryptPreKeyWhisperMessage(Buffer.from([0x33])), /Message too short/)
    await assert.rejects(
      () => bobCipher.decryptPreKeyWhisperMessage(Buffer.alloc(64, 0x22)),
      /Incompatible version/
    )
  })

  it("serializes and restores a session record", async () => {
    const { alice, aliceCipher } = await makePair()
    await aliceCipher.encrypt(Buffer.from("serializable"))

    const record = await alice.storage.loadSession("bob.1")
    assert.ok(record instanceof SessionRecord)

    const serialized = record.serialize()
    const restored = SessionRecord.deserialize(serialized)
    assert.deepEqual(restored.serialize(), serialized)
    assert.equal(restored.haveOpenSession(), true)
  })

  it("closes the open session on demand", async () => {
    const { aliceCipher } = await makePair()
    assert.equal(await aliceCipher.hasOpenSession(), true)

    await aliceCipher.closeOpenSession()
    assert.equal(await aliceCipher.hasOpenSession(), false)
    await assert.rejects(() => aliceCipher.encrypt(Buffer.from("x")), /No open session/)
  })

  it("rejects a bundle with an invalid signature", async () => {
    const alice = createMemoryParty("alice")
    const bob = createMemoryParty("bob")
    bob.addSignedPreKey(1)
    const bundle = bob.bundle()
    bundle.signedPreKey.signature = Buffer.from(bundle.signedPreKey.signature)
    bundle.signedPreKey.signature[0] ^= 0xff

    await assert.rejects(() => alice.builderFor("bob").initOutgoing(bundle), /Signature validation failed/)
  })

  it("validates device key bundles", async () => {
    const bob = createMemoryParty("bob")
    bob.addSignedPreKey(1)
    const alice = createMemoryParty("alice")

    await assert.rejects(() => alice.builderFor("bob").initOutgoing({ ...bob.bundle(), registrationId: 0 }))
    await assert.rejects(() => alice.builderFor("bob").initOutgoing({ ...bob.bundle(), identityKey: Buffer.alloc(32) }))
  })

  it("keeps identity trust decisions constant-size compared and persistent", async () => {
    const bob = createMemoryParty("bob")
    assert.equal(await bob.storage.isTrustedIdentity("alice", bob.identity.pubKey, 1), true)
    assert.equal(await bob.storage.isTrustedIdentity("alice", Buffer.alloc(33, 1), 1), false)
    assert.equal(await bob.storage.saveIdentity("alice", Buffer.alloc(33, 2)), true)
    assert.equal(await bob.storage.saveIdentity("alice", Buffer.alloc(33, 2)), false)
  })

  it("stores sessions separately per protocol address", async () => {
    const alice = createMemoryParty("alice")
    const bob1 = createMemoryParty("bob")
    // Both addresses share the same identity key, as the trust store is keyed
    // by identifier rather than by device.
    const bob2 = createMemoryPartyWithIdentity("bob", bob1.identity)
    bob1.addSignedPreKey(1)
    bob1.addPreKey(1)
    bob2.addSignedPreKey(1)
    bob2.addPreKey(1)

    await alice.builderFor("bob", 1).initOutgoing(bob1.bundle())
    await alice.builderFor("bob", 2).initOutgoing(bob2.bundle())

    const m1 = await alice.cipherFor("bob", 1).encrypt(Buffer.from("device 1"))
    const m2 = await alice.cipherFor("bob", 2).encrypt(Buffer.from("device 2"))

    assert.deepEqual(await bob1.cipherFor("alice").decryptPreKeyWhisperMessage(m1.body), Buffer.from("device 1"))
    assert.deepEqual(await bob2.cipherFor("alice").decryptPreKeyWhisperMessage(m2.body), Buffer.from("device 2"))
  })

  it("validates incoming prekey message fields", () => {
    const alice = createMemoryParty("alice")
    const valid = {
      registrationId: 1,
      identityKey: alice.identity.pubKey,
      baseKey: alice.identity.pubKey,
      signedPreKeyId: 1,
      message: Buffer.alloc(16, 1)
    }

    assert.doesNotThrow(() => assertValidIncomingPreKeyMessage(valid))
    assert.throws(() => assertValidIncomingPreKeyMessage({ ...valid, identityKey: Buffer.alloc(32) }), /identityKey/)
    assert.throws(() => assertValidIncomingPreKeyMessage({ ...valid, baseKey: Buffer.alloc(32) }), /baseKey/)
    assert.throws(
      () => assertValidIncomingPreKeyMessage({ ...valid, message: Buffer.alloc(0) }),
      /message must be a non-empty/
    )
    assert.throws(
      () => assertValidIncomingPreKeyMessage({ ...valid, registrationId: 0 }),
      /registrationId/
    )
    assert.throws(
      () => assertValidIncomingPreKeyMessage({ ...valid, signedPreKeyId: undefined }),
      /signedPreKeyId/
    )
  })

  it("rejects malformed prekey wire messages", async () => {
    const alice = createMemoryParty("alice")
    const cipher = alice.cipherFor("bob")
    const encodePreKey = (fields) =>
      Buffer.concat([
        Buffer.from([0x33]),
        Buffer.from(protobufs.PreKeyWhisperMessage.encode(protobufs.PreKeyWhisperMessage.create(fields)).finish())
      ])

    const base = {
      registrationId: 1,
      identityKey: Buffer.alloc(33, 1),
      baseKey: Buffer.alloc(33, 2),
      signedPreKeyId: 1,
      message: Buffer.alloc(16, 3)
    }

    await assert.rejects(
      () => cipher.decryptPreKeyWhisperMessage(encodePreKey({ ...base, identityKey: Buffer.alloc(32) })),
      /identityKey/
    )
    await assert.rejects(
      () => cipher.decryptPreKeyWhisperMessage(encodePreKey({ ...base, baseKey: Buffer.alloc(32) })),
      /baseKey/
    )
    await assert.rejects(
      () => cipher.decryptPreKeyWhisperMessage(encodePreKey({ ...base, signedPreKeyId: undefined })),
      /Missing SignedPreKey/
    )
  })

  it("reports malformed protobuf payloads with contextual errors", async () => {
    const alice = createMemoryParty("alice")
    const cipher = alice.cipherFor("bob")
    const invalid = Buffer.from([0x33, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0])

    await assert.rejects(
      () => cipher.decryptPreKeyWhisperMessage(invalid),
      /Invalid PreKeyWhisperMessage/
    )

    const pair = await makePair()
    const record = await pair.alice.storage.loadSession("bob.1")
    assert.ok(record)
    const session = record.getOpenSession()
    assert.ok(session)
    await assert.rejects(
      () => pair.aliceCipher.doDecryptWhisperMessage(invalid, session),
      /Invalid WhisperMessage/
    )
  })

  it("rejects malformed whisper messages before ratcheting", async () => {
    const { alice, aliceCipher } = await makePair()
    const record = await alice.storage.loadSession("bob.1")
    assert.ok(record)
    const session = record.getOpenSession()
    assert.ok(session)

    const encodeWhisper = (fields) => {
      const encoded = protobufs.WhisperMessage.encode(protobufs.WhisperMessage.create(fields)).finish()
      return Buffer.concat([Buffer.from([0x33]), Buffer.from(encoded), Buffer.alloc(8)])
    }

    await assert.rejects(
      () =>
        aliceCipher.doDecryptWhisperMessage(
          encodeWhisper({
            ephemeralKey: Buffer.alloc(32),
            counter: 1,
            previousCounter: 0,
            ciphertext: Buffer.alloc(16)
          }),
          session
        ),
      /ephemeralKey/
    )

    await assert.rejects(
      () =>
        aliceCipher.doDecryptWhisperMessage(
          encodeWhisper({
            ephemeralKey: Buffer.alloc(33),
            counter: 1,
            previousCounter: 0,
            ciphertext: Buffer.alloc(15)
          }),
          session
        ),
      /ciphertext/
    )
  })
})
