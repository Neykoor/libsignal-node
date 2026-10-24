import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { hkdfSync, randomBytes } from "node:crypto"
import { crypto } from "../lib/index.js"

describe("crypto", () => {
  const salt = Buffer.alloc(32, 7)
  const ikm = randomBytes(32)
  const info = Buffer.from("WhisperMessageKeys")

  it("implements RFC 5869 HKDF-SHA256 in 32-byte chunks", () => {
    for (const chunks of [1, 2, 3]) {
      const parts = crypto.deriveSecrets(ikm, salt, info, chunks)
      assert.equal(parts.length, chunks)
      const expected = Buffer.from(hkdfSync("sha256", ikm, salt, info, chunks * 32))
      assert.deepEqual(Buffer.concat(parts), expected)
    }
  })

  it("rejects invalid salt and chunk counts", () => {
    assert.throws(() => crypto.deriveSecrets(ikm, Buffer.alloc(16), info), /salt of incorrect length/)
    assert.throws(() => crypto.deriveSecrets(ikm, salt, info, 0), /chunks must be between 1 and 3/)
    assert.throws(() => crypto.deriveSecrets(ikm, salt, info, 4), /chunks must be between 1 and 3/)
    assert.throws(() => crypto.deriveSecrets(ikm, salt, info, Number.NaN), /chunks must be between 1 and 3/)
  })

  it("encrypts and decrypts AES-256-CBC", () => {
    const key = randomBytes(32)
    const iv = randomBytes(16)
    const plaintext = Buffer.from("mensaje secreto")
    const ciphertext = crypto.encrypt(key, plaintext, iv)
    assert.notDeepEqual(ciphertext, plaintext)
    assert.deepEqual(crypto.decrypt(key, ciphertext, iv), plaintext)
  })

  it("fails to decrypt with the wrong key", () => {
    const key = randomBytes(32)
    const iv = randomBytes(16)
    const ciphertext = crypto.encrypt(key, Buffer.from("x"), iv)
    assert.throws(() => crypto.decrypt(randomBytes(32), ciphertext, iv))
  })

  it("calculates and verifies MACs", () => {
    const key = randomBytes(32)
    const data = Buffer.from("data")
    const mac = crypto.calculateMAC(key, data)
    assert.equal(mac.length, 32)
    assert.equal(crypto.calculateMAC(key, data).equals(mac), true)
    assert.doesNotThrow(() => crypto.verifyMAC(data, key, mac.subarray(0, 8), 8))
    assert.throws(() => crypto.verifyMAC(Buffer.from("other"), key, mac.subarray(0, 8), 8), /Bad MAC/)
    assert.throws(() => crypto.verifyMAC(data, key, mac.subarray(0, 7), 8), /Bad MAC length/)
  })

  it("hashes with SHA-512", () => {
    assert.equal(crypto.hash(Buffer.from("abc")).length, 64)
    assert.notDeepEqual(crypto.hash(Buffer.from("abc")), crypto.hash(Buffer.from("abd")))
  })

  it("rejects non-buffer inputs", () => {
    assert.throws(() => crypto.encrypt("not a buffer", Buffer.alloc(1), Buffer.alloc(16)), TypeError)
    assert.throws(() => crypto.hash("not a buffer"), TypeError)
  })
})
