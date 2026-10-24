import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { createRequire } from "node:module"
import {
  MemorySignalStorage,
  ProtocolAddress,
  SessionCipher,
  SessionRecord,
  curve,
  keyhelper,
  protobufs
} from "../lib/index.js"
import * as ours from "../lib/index.js"
import { createMemoryParty } from "./helpers.mjs"

const require = createRequire(import.meta.url)
const upstream = require("libsignal")
const upstreamProtobufs = require("libsignal/src/protobufs")

/**
 * Minimal SignalStorage implementation backed by the upstream libsignal
 * package. It intentionally keeps its own SessionRecord instances: both
 * implementations must interoperate through the wire format, not by sharing
 * in-memory objects.
 */
class UpstreamParty {
  constructor(identifier, identity = upstream.keyhelper.generateIdentityKeyPair(), registrationId) {
    this.identifier = identifier
    this.identity = identity
    this.registrationId = registrationId ?? keyhelper.generateRegistrationId()
    this.sessions = new Map()
    this.preKeys = new Map()
    this.signedPreKeys = new Map()
    this.trustedIdentities = new Map()

    const party = this
    this.storage = {
      async loadSession(id) {
        return party.sessions.get(id)
      },
      async storeSession(id, session) {
        party.sessions.set(id, session)
      },
      isTrustedIdentity(identifier, identityKey) {
        const existing = party.trustedIdentities.get(identifier)
        if (!existing) {
          party.trustedIdentities.set(identifier, Buffer.from(identityKey))
          return true
        }

        return existing.equals(Buffer.from(identityKey))
      },
      async loadPreKey(id) {
        return party.preKeys.get(Number(id))?.keyPair
      },
      removePreKey(id) {
        party.preKeys.delete(Number(id))
      },
      async loadSignedPreKey(id) {
        return party.signedPreKeys.get(Number(id))?.keyPair
      },
      getOurRegistrationId() {
        return party.registrationId
      },
      getOurIdentity() {
        return party.identity
      }
    }
  }

  addSignedPreKey(keyId, record = upstream.keyhelper.generateSignedPreKey(this.identity, keyId)) {
    this.signedPreKeys.set(keyId, record)
    return record
  }

  addPreKey(keyId, record = upstream.keyhelper.generatePreKey(keyId)) {
    this.preKeys.set(keyId, record)
    return record
  }

  bundle({ preKeyId = 1, signedPreKeyId = 1 } = {}) {
    const signed = this.signedPreKeys.get(signedPreKeyId)
    const preKey = this.preKeys.get(preKeyId)
    if (!signed) {
      throw new Error(`Missing signed prekey ${signedPreKeyId}`)
    }

    return {
      registrationId: this.registrationId,
      identityKey: this.identity.pubKey,
      signedPreKey: {
        keyId: signed.keyId,
        publicKey: signed.keyPair.pubKey,
        signature: signed.signature
      },
      ...(preKey ? { preKey: { keyId: preKey.keyId, publicKey: preKey.keyPair.pubKey } } : {})
    }
  }

  address(deviceId = 1) {
    return new upstream.ProtocolAddress(this.identifier, deviceId)
  }

  builderFor(remoteIdentifier, deviceId = 1) {
    return new upstream.SessionBuilder(this.storage, new upstream.ProtocolAddress(remoteIdentifier, deviceId))
  }

  cipherFor(remoteIdentifier, deviceId = 1) {
    return new upstream.SessionCipher(this.storage, new upstream.ProtocolAddress(remoteIdentifier, deviceId))
  }

  exportSession(remoteIdentifier, deviceId = 1) {
    const record = this.sessions.get(`${remoteIdentifier}.${deviceId}`)
    if (!record) {
      throw new Error("No upstream session to export")
    }

    return record.serialize()
  }

  importSession(remoteIdentifier, serialized, deviceId = 1) {
    this.sessions.set(`${remoteIdentifier}.${deviceId}`, upstream.SessionRecord.deserialize(serialized))
  }
}

describe("interop with upstream libsignal", () => {
  it("exposes the same public API as upstream", () => {
    for (const name of Object.keys(upstream)) {
      assert.ok(name in ours, `missing export: ${name}`)
    }

    for (const namespace of ["crypto", "curve", "keyhelper"]) {
      for (const name of Object.keys(upstream[namespace])) {
        assert.equal(typeof ours[namespace][name], "function", `missing function: ${namespace}.${name}`)
      }
    }
  })

  it("our initiator talks to an upstream responder", async () => {
    const alice = createMemoryParty("alice")
    const bob = new UpstreamParty("bob")
    bob.addSignedPreKey(1)
    bob.addPreKey(1)

    await alice.builderFor("bob").initOutgoing(bob.bundle())

    const aliceCipher = alice.cipherFor("bob")
    const bobCipher = bob.cipherFor("alice")

    const first = await aliceCipher.encrypt(Buffer.from("hola desde alice"))
    assert.equal(first.type, 3)
    assert.deepEqual(await bobCipher.decryptPreKeyWhisperMessage(first.body), Buffer.from("hola desde alice"))

    const reply = await bobCipher.encrypt(Buffer.from("hola desde bob"))
    assert.equal(reply.type, 1)
    assert.deepEqual(await aliceCipher.decryptWhisperMessage(reply.body), Buffer.from("hola desde bob"))

    for (let i = 0; i < 3; i++) {
      const message = await aliceCipher.encrypt(Buffer.from(`alice ${i}`))
      assert.deepEqual(await bobCipher.decryptWhisperMessage(message.body), Buffer.from(`alice ${i}`))

      const response = await bobCipher.encrypt(Buffer.from(`bob ${i}`))
      assert.deepEqual(await aliceCipher.decryptWhisperMessage(response.body), Buffer.from(`bob ${i}`))
    }
  })

  it("an upstream initiator talks to our responder", async () => {
    const alice = new UpstreamParty("alice")
    const bob = createMemoryParty("bob")
    bob.addSignedPreKey(1)
    bob.addPreKey(1)

    await alice.builderFor("bob").initOutgoing(bob.bundle())

    const aliceCipher = alice.cipherFor("bob")
    const bobCipher = bob.cipherFor("alice")

    const first = await aliceCipher.encrypt(Buffer.from("hola desde upstream alice"))
    assert.equal(first.type, 3)
    assert.deepEqual(
      await bobCipher.decryptPreKeyWhisperMessage(first.body),
      Buffer.from("hola desde upstream alice")
    )

    const reply = await bobCipher.encrypt(Buffer.from("hola desde nuestro bob"))
    assert.equal(reply.type, 1)
    assert.deepEqual(await aliceCipher.decryptWhisperMessage(reply.body), Buffer.from("hola desde nuestro bob"))

    for (let i = 0; i < 3; i++) {
      const message = await aliceCipher.encrypt(Buffer.from(`upstream alice ${i}`))
      assert.deepEqual(await bobCipher.decryptWhisperMessage(message.body), Buffer.from(`upstream alice ${i}`))

      const response = await bobCipher.encrypt(Buffer.from(`nuestro bob ${i}`))
      assert.deepEqual(await aliceCipher.decryptWhisperMessage(response.body), Buffer.from(`nuestro bob ${i}`))
    }
  })

  it("loads a session serialized by us with upstream SessionRecord", async () => {
    const alice = createMemoryParty("alice")
    const bob = new UpstreamParty("bob")
    bob.addSignedPreKey(1)
    bob.addPreKey(1)

    await alice.builderFor("bob").initOutgoing(bob.bundle())
    const aliceCipher = alice.cipherFor("bob")
    const bobCipher = bob.cipherFor("alice")

    await bobCipher.decryptPreKeyWhisperMessage((await aliceCipher.encrypt(Buffer.from("inicio"))).body)
    await aliceCipher.decryptWhisperMessage((await bobCipher.encrypt(Buffer.from("respuesta"))).body)

    const record = await alice.storage.loadSession("bob.1")
    assert.ok(record)
    const serialized = JSON.parse(record.serialize().toString("utf-8"))

    const aliceClone = new UpstreamParty("alice", alice.identity, alice.registrationId)
    aliceClone.importSession("bob", serialized)

    const message = await bobCipher.encrypt(Buffer.from("despues de importar"))
    const plaintext = await aliceClone.cipherFor("bob").decryptWhisperMessage(message.body)
    assert.deepEqual(plaintext, Buffer.from("despues de importar"))
  })

  it("loads an upstream session serialized with our SessionRecord", async () => {
    const alice = createMemoryParty("alice")
    const bob = new UpstreamParty("bob")
    bob.addSignedPreKey(1)
    bob.addPreKey(1)

    await alice.builderFor("bob").initOutgoing(bob.bundle())
    const aliceCipher = alice.cipherFor("bob")
    const bobCipher = bob.cipherFor("alice")

    await bobCipher.decryptPreKeyWhisperMessage((await aliceCipher.encrypt(Buffer.from("inicio"))).body)
    await aliceCipher.decryptWhisperMessage((await bobCipher.encrypt(Buffer.from("respuesta"))).body)

    const serialized = bob.exportSession("alice")
    const record = SessionRecord.deserialize(Buffer.from(JSON.stringify(serialized)))

    const bobStorage = new MemorySignalStorage(bob.identity, bob.registrationId)
    await bobStorage.storeSession("alice.1", record)
    const bobClone = new SessionCipher(bobStorage, new ProtocolAddress("alice", 1))

    const message = await aliceCipher.encrypt(Buffer.from("despues de importar upstream"))
    assert.deepEqual(await bobClone.decryptWhisperMessage(message.body), Buffer.from("despues de importar upstream"))
  })

  it("shares X25519 agreements and Ed25519 signatures with upstream", () => {
    const alice = upstream.keyhelper.generateIdentityKeyPair()
    const bob = curve.generateKeyPair()

    assert.deepEqual(
      curve.calculateAgreement(bob.pubKey, alice.privKey),
      upstream.curve.calculateAgreement(bob.pubKey, alice.privKey)
    )
    assert.deepEqual(
      curve.getPublicFromPrivateKey(alice.privKey),
      upstream.curve.getPublicFromPrivateKey(alice.privKey)
    )

    const message = Buffer.from("firma interoperable")
    const ourSignature = curve.calculateSignature(alice.privKey, message)
    const theirSignature = upstream.curve.calculateSignature(alice.privKey, message)

    assert.equal(upstream.curve.verifySignature(alice.pubKey, message, ourSignature), true)
    assert.equal(curve.verifySignature(alice.pubKey, message, theirSignature), true)
  })

  it("encodes WhisperMessage and PreKeyWhisperMessage like upstream", () => {
    const whisperFields = {
      ephemeralKey: Buffer.alloc(33, 7),
      counter: 42,
      previousCounter: 3,
      ciphertext: Buffer.from("ciphertext de prueba")
    }

    const ourWhisper = protobufs.WhisperMessage.encode(protobufs.WhisperMessage.create(whisperFields)).finish()
    const theirWhisper = upstreamProtobufs.WhisperMessage.encode(
      upstreamProtobufs.WhisperMessage.create(whisperFields)
    ).finish()
    assert.deepEqual(Buffer.from(ourWhisper), Buffer.from(theirWhisper))

    const preKeyFields = {
      registrationId: 1234,
      preKeyId: 7,
      signedPreKeyId: 11,
      baseKey: Buffer.alloc(33, 9),
      identityKey: Buffer.alloc(33, 5),
      message: Buffer.from("mensaje interno")
    }

    const ourPreKey = protobufs.PreKeyWhisperMessage.encode(
      protobufs.PreKeyWhisperMessage.create(preKeyFields)
    ).finish()
    const theirPreKey = upstreamProtobufs.PreKeyWhisperMessage.encode(
      upstreamProtobufs.PreKeyWhisperMessage.create(preKeyFields)
    ).finish()
    assert.deepEqual(Buffer.from(ourPreKey), Buffer.from(theirPreKey))

    assert.deepEqual(
      Buffer.from(protobufs.PreKeyWhisperMessage.decode(theirPreKey).message),
      preKeyFields.message
    )
  })
})
