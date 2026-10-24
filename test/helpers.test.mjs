import { describe, it } from "node:test"
import assert from "node:assert/strict"
import {
  FingerprintGenerator,
  ProtocolAddress,
  assertValidDeviceKeyBundle,
  curve,
  keyhelper
} from "../lib/index.js"
import { PreKeyError } from "../lib/errors.js"

describe("keyhelper", () => {
  it("generates registration ids inside the 14-bit range", () => {
    for (let i = 0; i < 100; i++) {
      const id = keyhelper.generateRegistrationId()
      assert.ok(Number.isInteger(id))
      assert.ok(id >= 1 && id <= 0x3fff)
    }
  })

  it("wraps prekey ids inside the 24-bit range", () => {
    assert.equal(keyhelper.wrapPreKeyId(1), 1)
    assert.equal(keyhelper.wrapPreKeyId(0xffffff), 0xffffff)
    assert.equal(keyhelper.wrapPreKeyId(0x1000000), 1)
  })

  it("generates signed prekeys whose signatures verify", () => {
    const identity = keyhelper.generateIdentityKeyPair()
    const signed = keyhelper.generateSignedPreKey(identity, 7)
    assert.equal(signed.keyId, 7)
    assert.equal(signed.keyPair.pubKey.length, 33)
    assert.equal(signed.signature.length, 64)
    assert.equal(curve.verifySignature(identity.pubKey, signed.keyPair.pubKey, signed.signature), true)
  })

  it("generates prekeys and batches with unique ids", async () => {
    const prekey = keyhelper.generatePreKey(3)
    assert.equal(prekey.keyId, 3)
    assert.equal(prekey.keyPair.privKey.length, 32)

    const batch = await keyhelper.generatePreKeysBatch(10, 20)
    assert.equal(batch.length, 20)
    assert.deepEqual(batch.map((key) => key.keyId), Array.from({ length: 20 }, (_, i) => i + 10))
    assert.equal(new Set(batch.map((key) => key.keyPair.pubKey.toString("hex"))).size, 20)
  })

  it("validates signed prekey rotation age", () => {
    assert.equal(keyhelper.shouldRotateSignedPreKey(Date.now() - 1000, 500), true)
    assert.equal(keyhelper.shouldRotateSignedPreKey(Date.now() - 1000, 5000), false)
    assert.throws(() => keyhelper.shouldRotateSignedPreKey(-1), TypeError)
    assert.throws(() => keyhelper.shouldRotateSignedPreKey(1, -1), TypeError)
  })

  it("rejects invalid key helper arguments", async () => {
    const identity = keyhelper.generateIdentityKeyPair()
    assert.throws(() => keyhelper.generateSignedPreKey({ ...identity, privKey: Buffer.alloc(31) }, 1), TypeError)
    assert.throws(() => keyhelper.generateSignedPreKey(identity, -1), TypeError)
    assert.throws(() => keyhelper.generatePreKey(-1), TypeError)
    await assert.rejects(() => keyhelper.generatePreKeysBatch(-1, 2), TypeError)
    await assert.rejects(() => keyhelper.generatePreKeysBatch(1, 0), TypeError)
  })
})

describe("prekey bundle validator", () => {
  function validBundle() {
    const identity = keyhelper.generateIdentityKeyPair()
    const signed = keyhelper.generateSignedPreKey(identity, 1)
    const prekey = keyhelper.generatePreKey(2)
    return {
      registrationId: 1234,
      identityKey: identity.pubKey,
      signedPreKey: {
        keyId: signed.keyId,
        publicKey: signed.keyPair.pubKey,
        signature: signed.signature
      },
      preKey: { keyId: prekey.keyId, publicKey: prekey.keyPair.pubKey }
    }
  }

  it("accepts a valid bundle", () => {
    assert.doesNotThrow(() => assertValidDeviceKeyBundle(validBundle()))
  })

  it("rejects invalid registration ids", () => {
    for (const registrationId of [0, -1, 0x4000, 1.5, NaN]) {
      assert.throws(() => assertValidDeviceKeyBundle({ ...validBundle(), registrationId }), PreKeyError)
    }
  })

  it("rejects invalid key lengths", () => {
    const bundle = validBundle()
    assert.throws(() => assertValidDeviceKeyBundle({ ...bundle, identityKey: Buffer.alloc(32) }), PreKeyError)
    assert.throws(
      () => assertValidDeviceKeyBundle({ ...bundle, signedPreKey: { ...bundle.signedPreKey, publicKey: Buffer.alloc(32) } }),
      PreKeyError
    )
    assert.throws(
      () => assertValidDeviceKeyBundle({ ...bundle, signedPreKey: { ...bundle.signedPreKey, signature: Buffer.alloc(63) } }),
      PreKeyError
    )
    assert.throws(
      () => assertValidDeviceKeyBundle({ ...bundle, preKey: { ...bundle.preKey, publicKey: Buffer.alloc(32) } }),
      PreKeyError
    )
  })

  it("rejects invalid key ids and missing signed prekeys", () => {
    const bundle = validBundle()
    assert.throws(
      () => assertValidDeviceKeyBundle({ ...bundle, signedPreKey: { ...bundle.signedPreKey, keyId: -1 } }),
      PreKeyError
    )
    assert.throws(
      () => assertValidDeviceKeyBundle({ ...bundle, signedPreKey: { ...bundle.signedPreKey, keyId: 0x1000000 } }),
      PreKeyError
    )
    assert.throws(() => assertValidDeviceKeyBundle({ ...bundle, signedPreKey: null }), PreKeyError)
  })
})

describe("ProtocolAddress", () => {
  it("parses and formats addresses", () => {
    const address = ProtocolAddress.from("5215512345678.3")
    assert.equal(address.id, "5215512345678")
    assert.equal(address.deviceId, 3)
    assert.equal(address.toString(), "5215512345678.3")
    assert.equal(address.is(new ProtocolAddress("5215512345678", 3)), true)
    assert.equal(address.is(new ProtocolAddress("5215512345678", 4)), false)
    assert.equal(address.is({}), false)
  })

  it("rejects invalid addresses", () => {
    assert.throws(() => ProtocolAddress.from("sin-dispositivo"), /Invalid address encoding/)
    assert.throws(() => ProtocolAddress.from("user.abc"), /Invalid address encoding/)
    assert.throws(() => new ProtocolAddress("user.1", 1), /encoded addr detected/)
    assert.throws(() => new ProtocolAddress(1, 1), TypeError)
    assert.throws(() => new ProtocolAddress("user", "1"), TypeError)
  })
})

describe("FingerprintGenerator", () => {
  const aliceIdentity = Buffer.from([
    0x05, 0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4, 0x0d, 0x27, 0xb8, 0xd4, 0x9c, 0xa7, 0xc0, 0x9e,
    0x92, 0x39, 0x23, 0x6f, 0x9d, 0x7d, 0x25, 0xd6, 0xfc, 0xca, 0x5c, 0xe1, 0x3c, 0x70, 0x64, 0xd8,
    0x68
  ])
  const bobIdentity = Buffer.from([
    0x05, 0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9, 0xba, 0x1c, 0xf2, 0xde, 0x97, 0x8d, 0x4d, 0x5d,
    0xa2, 0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81, 0x44, 0x02, 0xb5, 0xc0, 0xdb, 0xd9, 0x6f, 0xda, 0x90,
    0x7b
  ])

  it("matches the well-known Signal fingerprint vector", async () => {
    const generator = new FingerprintGenerator(5200)
    const fingerprint = await generator.createFor(
      "+14152222222",
      aliceIdentity,
      "+14153333333",
      bobIdentity
    )
    assert.equal(fingerprint, "300354477692869396892869876765458257569162576843440918079131")
  })

  it("produces the same fingerprint from both sides", async () => {
    const generator = new FingerprintGenerator(1024)
    const alice = await generator.createFor("+14152222222", aliceIdentity, "+14153333333", bobIdentity)
    const bob = await generator.createFor("+14153333333", bobIdentity, "+14152222222", aliceIdentity)
    assert.equal(alice, bob)
    assert.match(alice, /^\d{60}$/)
  })

  it("rejects invalid arguments", () => {
    const generator = new FingerprintGenerator(1024)
    assert.throws(() => generator.createFor(1, aliceIdentity, "bob", bobIdentity), /Invalid arguments/)
    assert.throws(() => generator.createFor("alice", "not a key", "bob", bobIdentity), /Invalid arguments/)
  })
})
