import { describe, it } from "node:test"
import assert from "node:assert/strict"
import {
  GroupCipher,
  GroupSessionBuilder,
  ProtocolAddress,
  SenderKeyDistributionMessage,
  SenderKeyError,
  SenderKeyMessage,
  SenderKeyName,
  SenderKeyRecord
} from "../lib/index.js"
import { createMemoryParty, flipByte } from "./helpers.mjs"

function parseMessage(buffer) {
  return new SenderKeyMessage(undefined, undefined, undefined, undefined, buffer)
}

async function establishGroup(groupId = "grupo@test") {
  const alice = createMemoryParty("alice")
  const bob = createMemoryParty("bob")
  const aliceName = new SenderKeyName(groupId, new ProtocolAddress("alice", 1))
  const bobViewOfAlice = new SenderKeyName(groupId, new ProtocolAddress("alice", 1))
  const aliceBuilder = new GroupSessionBuilder(alice.storage)
  const bobBuilder = new GroupSessionBuilder(bob.storage)

  const distribution = await aliceBuilder.create(aliceName)
  await bobBuilder.process(
    bobViewOfAlice,
    new SenderKeyDistributionMessage(undefined, undefined, undefined, undefined, distribution.serialize())
  )

  return {
    alice,
    bob,
    aliceName,
    bobViewOfAlice,
    aliceBuilder,
    bobBuilder,
    aliceCipher: new GroupCipher(alice.storage, aliceName),
    bobCipher: new GroupCipher(bob.storage, bobViewOfAlice)
  }
}

describe("Sender Key groups", () => {
  it("encrypts and decrypts group messages sequentially", async () => {
    const { aliceCipher, bobCipher } = await establishGroup()

    for (let i = 0; i < 5; i++) {
      const encrypted = await aliceCipher.encrypt(Buffer.from(`mensaje ${i}`))
      const message = parseMessage(encrypted)
      assert.equal(message.getIteration(), i, "each message must consume exactly one chain iteration")
      assert.deepEqual(await bobCipher.decrypt(encrypted), Buffer.from(`mensaje ${i}`))
    }
  })

  it("decrypts out-of-order group messages", async () => {
    const { aliceCipher, bobCipher } = await establishGroup()
    const messages = []
    for (let i = 0; i < 5; i++) {
      messages.push(await aliceCipher.encrypt(Buffer.from(`m${i}`)))
    }

    for (const index of [0, 2, 4, 1, 3]) {
      assert.deepEqual(await bobCipher.decrypt(messages[index]), Buffer.from(`m${index}`))
    }
  })

  it("rejects tampered group messages", async () => {
    const { aliceCipher, bobCipher } = await establishGroup()
    const encrypted = await aliceCipher.encrypt(Buffer.from("integro"))

    // Flip the last ciphertext byte (immediately before the 64-byte signature)
    // so the protobuf still decodes and the failure comes from the signature.
    const tamperedCiphertext = flipByte(encrypted, encrypted.length - 65)
    await assert.rejects(() => bobCipher.decrypt(tamperedCiphertext), /Invalid signature/)

    const tamperedSignature = flipByte(encrypted, encrypted.length - 1)
    await assert.rejects(() => bobCipher.decrypt(tamperedSignature), /Invalid signature/)
  })

  it("rejects messages for an unknown sender key id", async () => {
    const { alice, bob, aliceName, bobViewOfAlice, aliceCipher } = await establishGroup()
    const aliceRecord = await alice.storage.loadSenderKey(aliceName)
    assert.ok(aliceRecord instanceof SenderKeyRecord)
    const state = aliceRecord.getSenderKeyState()
    assert.ok(state)

    const encrypted = await aliceCipher.encrypt(Buffer.from("desconocido"))
    const message = parseMessage(encrypted)
    const forged = new SenderKeyMessage(
      message.getKeyId() + 1,
      message.getIteration(),
      message.getCipherText(),
      state.getSigningKeyPrivate()
    )

    const bobCipher = new GroupCipher(bob.storage, bobViewOfAlice)
    await assert.rejects(() => bobCipher.decrypt(forged.serialize()), SenderKeyError)
  })

  it("rotates sender keys and keeps old messages readable", async () => {
    const { aliceBuilder, bobBuilder, aliceName, bobViewOfAlice, aliceCipher, bobCipher } =
      await establishGroup()

    const oldMessage = await aliceCipher.encrypt(Buffer.from("antes"))
    const oldDistribution = await aliceBuilder.create(aliceName)
    const oldKeyId = new SenderKeyDistributionMessage(
      undefined,
      undefined,
      undefined,
      undefined,
      oldDistribution.serialize()
    ).getId()

    const newDistribution = await aliceBuilder.rotate(aliceName)
    const parsedNew = new SenderKeyDistributionMessage(
      undefined,
      undefined,
      undefined,
      undefined,
      newDistribution.serialize()
    )
    assert.notEqual(parsedNew.getId(), oldKeyId)
    assert.equal(parsedNew.getIteration(), 0)

    const newMessage = await aliceCipher.encrypt(Buffer.from("despues"))

    // The receiver does not know the new key yet.
    await assert.rejects(() => bobCipher.decrypt(newMessage), SenderKeyError)

    await bobBuilder.process(bobViewOfAlice, parsedNew)
    assert.deepEqual(await bobCipher.decrypt(newMessage), Buffer.from("despues"))
    assert.deepEqual(await bobCipher.decrypt(oldMessage), Buffer.from("antes"))
  })

  it("does not reset the sender chain when create is called again", async () => {
    const { aliceBuilder, aliceName, aliceCipher } = await establishGroup()
    const first = new SenderKeyDistributionMessage(
      undefined,
      undefined,
      undefined,
      undefined,
      (await aliceBuilder.create(aliceName)).serialize()
    )
    await aliceCipher.encrypt(Buffer.from("1"))
    await aliceCipher.encrypt(Buffer.from("2"))

    const second = new SenderKeyDistributionMessage(
      undefined,
      undefined,
      undefined,
      undefined,
      (await aliceBuilder.create(aliceName)).serialize()
    )
    assert.equal(second.getId(), first.getId())
    assert.equal(second.getIteration(), 2)
  })

  it("rejects malformed sender key distribution messages", async () => {
    const { bobBuilder, bobViewOfAlice } = await establishGroup()
    const badChain = new SenderKeyDistributionMessage(1, 0, Buffer.alloc(31), Buffer.alloc(33))
    await assert.rejects(() => bobBuilder.process(bobViewOfAlice, badChain), /Invalid chain key length/)

    const badSignature = new SenderKeyDistributionMessage(1, 0, Buffer.alloc(32), Buffer.alloc(31))
    await assert.rejects(() => bobBuilder.process(bobViewOfAlice, badSignature), /Invalid signing key length/)
  })

  it("serializes sender key records without losing state", async () => {
    const { alice, aliceName, aliceCipher } = await establishGroup()
    await aliceCipher.encrypt(Buffer.from("x"))
    const record = await alice.storage.loadSenderKey(aliceName)
    assert.ok(record)

    const serialized = record.serialize()
    const restored = SenderKeyRecord.deserialize(serialized)
    assert.deepEqual(restored.serialize(), serialized)
    assert.deepEqual(restored.getSenderKeyState()?.getSenderChainKey().getSeed(), record.getSenderKeyState()?.getSenderChainKey().getSeed())
  })

  it("compares sender key names", () => {
    const a = new SenderKeyName("g", new ProtocolAddress("alice", 1))
    const b = new SenderKeyName("g", new ProtocolAddress("alice", 1))
    const c = new SenderKeyName("g", new ProtocolAddress("alice", 2))
    assert.equal(a.equals(b), true)
    assert.equal(a.equals(c), false)
    assert.equal(a.equals(null), false)
    assert.equal(a.hashCode(), b.hashCode())
    assert.equal(a.toString(), "g::alice::1")
  })
})
