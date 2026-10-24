import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { curve } from "../lib/index.js"

describe("curve", () => {
  it("generates 33-byte public keys and 32-byte private keys", () => {
    const keyPair = curve.generateKeyPair()
    assert.equal(keyPair.pubKey.length, 33)
    assert.equal(keyPair.pubKey[0], 5)
    assert.equal(keyPair.privKey.length, 32)
  })

  it("derives the public key from the private key", () => {
    for (let i = 0; i < 5; i++) {
      const keyPair = curve.generateKeyPair()
      assert.deepEqual(curve.getPublicFromPrivateKey(keyPair.privKey), keyPair.pubKey)
    }
  })

  it("agrees on both sides of an X25519 exchange", () => {
    const alice = curve.generateKeyPair()
    const bob = curve.generateKeyPair()
    const aliceSecret = curve.calculateAgreement(bob.pubKey, alice.privKey)
    const bobSecret = curve.calculateAgreement(alice.pubKey, bob.privKey)
    assert.equal(aliceSecret.length, 32)
    assert.deepEqual(aliceSecret, bobSecret)
  })

  it("accepts raw 32-byte public keys", () => {
    const alice = curve.generateKeyPair()
    const bob = curve.generateKeyPair()
    assert.deepEqual(
      curve.calculateAgreement(bob.pubKey.subarray(1), alice.privKey),
      curve.calculateAgreement(bob.pubKey, alice.privKey)
    )
  })

  it("rejects low-order public keys", () => {
    const alice = curve.generateKeyPair()
    assert.throws(
      () => curve.calculateAgreement(Buffer.concat([Buffer.from([5]), Buffer.alloc(32)]), alice.privKey),
      /invalid public key|failed during derivation/i
    )
  })

  it("signs and verifies messages", () => {
    const alice = curve.generateKeyPair()
    const message = Buffer.from("hola")
    const signature = curve.calculateSignature(alice.privKey, message)
    assert.equal(signature.length, 64)
    assert.equal(curve.verifySignature(alice.pubKey, message, signature), true)
    assert.equal(curve.verifySignature(alice.pubKey.subarray(1), message, signature), true)
    assert.equal(curve.verifySignature(alice.pubKey, Buffer.from("adios"), signature), false)
  })

  it("rejects malformed keys, messages and signatures", () => {
    const alice = curve.generateKeyPair()
    assert.throws(() => curve.calculateAgreement(Buffer.alloc(31), alice.privKey))
    assert.throws(() => curve.calculateAgreement(alice.pubKey, Buffer.alloc(31)))
    assert.throws(() => curve.verifySignature(alice.pubKey, Buffer.from("x"), Buffer.alloc(63)))
    assert.throws(() => curve.verifySignature(Buffer.alloc(31), Buffer.from("x"), Buffer.alloc(64)))
  })

  it("generates key pairs asynchronously", async () => {
    const keyPair = await curve.generateKeyPairAsync()
    assert.equal(keyPair.pubKey.length, 33)
    assert.equal(keyPair.privKey.length, 32)
  })
})
