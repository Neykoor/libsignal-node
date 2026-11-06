import { describe, it } from "node:test"
import assert from "node:assert/strict"
import {
  ChainType,
  GroupCipher,
  GroupSessionBuilder,
  ProtocolAddress,
  SenderKeyName
} from "../lib/index.js"
import { createMemoryParty, establishSession } from "./helpers.mjs"

function decryptAny(cipher, message) {
  return message.type === 3
    ? cipher.decryptPreKeyWhisperMessage(message.body)
    : cipher.decryptWhisperMessage(message.body)
}

async function makePair() {
  const alice = createMemoryParty("alice")
  const bob = createMemoryParty("bob")
  bob.addSignedPreKey(1)
  bob.addPreKey(1)
  const { senderCipher, recipientCipher } = await establishSession(alice, bob)
  return { alice, bob, aliceCipher: senderCipher, bobCipher: recipientCipher }
}

describe("Regressions", () => {
  it("keeps the signed prekey usable after the first incoming session", async () => {
    const alice = createMemoryParty("alice")
    const carol = createMemoryParty("carol")
    const bob = createMemoryParty("bob")
    bob.addSignedPreKey(1)
    bob.addPreKey(1)
    bob.addPreKey(2)

    const privateBefore = Buffer.from((await bob.storage.loadSignedPreKey(1)).privKey)

    await alice.builderFor("bob").initOutgoing(bob.bundle({ preKeyId: 1 }))
    await carol.builderFor("bob").initOutgoing(bob.bundle({ preKeyId: 2 }))
    const fromAlice = await alice.cipherFor("bob").encrypt(Buffer.from("hola desde alice"))
    const fromCarol = await carol.cipherFor("bob").encrypt(Buffer.from("hola desde carol"))

    assert.deepEqual(
      await bob.cipherFor("alice").decryptPreKeyWhisperMessage(fromAlice.body),
      Buffer.from("hola desde alice")
    )
    assert.deepEqual((await bob.storage.loadSignedPreKey(1)).privKey, privateBefore)

    assert.deepEqual(
      await bob.cipherFor("carol").decryptPreKeyWhisperMessage(fromCarol.body),
      Buffer.from("hola desde carol")
    )
    assert.deepEqual((await bob.storage.loadSignedPreKey(1)).privKey, privateBefore)
  })

  it("returns copies of stored prekeys", async () => {
    const bob = createMemoryParty("bob")
    bob.addSignedPreKey(1)
    bob.addPreKey(1)

    const signed = await bob.storage.loadSignedPreKey(1)
    const oneTime = await bob.storage.loadPreKey(1)
    signed.privKey.fill(0)
    oneTime.privKey.fill(0)

    assert.ok((await bob.storage.loadSignedPreKey(1)).privKey.some((byte) => byte !== 0))
    assert.ok((await bob.storage.loadPreKey(1)).privKey.some((byte) => byte !== 0))
  })

  it("limits the receiver chains kept per session", async () => {
    const { aliceCipher, bobCipher } = await makePair()

    for (let round = 0; round < 12; round++) {
      const out = await aliceCipher.encrypt(Buffer.from(`a${round}`))
      assert.deepEqual(await decryptAny(bobCipher, out), Buffer.from(`a${round}`))

      const back = await bobCipher.encrypt(Buffer.from(`b${round}`))
      assert.deepEqual(await decryptAny(aliceCipher, back), Buffer.from(`b${round}`))
    }

    for (const cipher of [aliceCipher, bobCipher]) {
      const session = (await cipher.getRecord()).getOpenSession()
      const receiving = Array.from(session.chains()).filter(([, chain]) => chain.chainType === ChainType.RECEIVING)
      assert.ok(receiving.length > 0)
      assert.ok(receiving.length <= 5)
    }
  })

  it("limits the skipped message keys stored per chain", async () => {
    const { aliceCipher, bobCipher } = await makePair()

    const first = await aliceCipher.encrypt(Buffer.from("hola"))
    await decryptAny(bobCipher, first)
    const reply = await bobCipher.encrypt(Buffer.from("respuesta"))
    await decryptAny(aliceCipher, reply)

    const messages = []
    for (let i = 0; i <= 3000; i++) {
      messages.push(await aliceCipher.encrypt(Buffer.from(`m${i}`)))
    }

    assert.deepEqual(await decryptAny(bobCipher, messages[1500]), Buffer.from("m1500"))
    assert.deepEqual(await decryptAny(bobCipher, messages[3000]), Buffer.from("m3000"))

    const session = (await bobCipher.getRecord()).getOpenSession()
    const counts = Array.from(session.chains()).map(([, chain]) => Object.keys(chain.messageKeys).length)
    assert.ok(Math.max(...counts) <= 2000)

    assert.deepEqual(await decryptAny(bobCipher, messages[2999]), Buffer.from("m2999"))
    await assert.rejects(decryptAny(bobCipher, messages[0]))
  })

  it("does not lose state when a sender key is distributed while a message is decrypted", async () => {
    const senderKeyName = new SenderKeyName("grupo@race", new ProtocolAddress("alice", 1))
    const alice = createMemoryParty("alice")
    const bob = createMemoryParty("bob")
    const aliceBuilder = new GroupSessionBuilder(alice.storage)
    const bobBuilder = new GroupSessionBuilder(bob.storage)

    const initial = await aliceBuilder.create(senderKeyName)
    await bobBuilder.process(senderKeyName, initial)

    const encrypted = await new GroupCipher(alice.storage, senderKeyName).encrypt(Buffer.from("hola"))
    const rotated = await aliceBuilder.rotate(senderKeyName)

    const originalLoad = bob.storage.loadSenderKey.bind(bob.storage)
    bob.storage.loadSenderKey = async (name) => {
      const record = await originalLoad(name)
      await new Promise((resolve) => setTimeout(resolve, 20))
      return record
    }

    const bobCipher = new GroupCipher(bob.storage, senderKeyName)
    const [plaintext] = await Promise.all([bobCipher.decrypt(encrypted), bobBuilder.process(senderKeyName, rotated)])
    assert.deepEqual(plaintext, Buffer.from("hola"))

    const record = await originalLoad(senderKeyName)
    assert.ok(record.getSenderKeyState(rotated.getId()))
    assert.equal(record.getSenderKeyState(initial.getId()).getSenderChainKey().getIteration(), 1)
  })
})
