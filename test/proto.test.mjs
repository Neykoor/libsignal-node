import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"
import { protobufs } from "../lib/index.js"

const rootDir = dirname(dirname(fileURLToPath(import.meta.url)))

describe("protobufs", () => {
  it("is exported from the package entry point", () => {
    assert.ok(protobufs)
    assert.equal(typeof protobufs.WhisperMessage.encode, "function")
    assert.equal(typeof protobufs.PreKeyWhisperMessage.encode, "function")
  })

  it("round-trips a PreKeyWhisperMessage", () => {
    const message = protobufs.PreKeyWhisperMessage.create({
      registrationId: 10,
      preKeyId: 2,
      signedPreKeyId: 3,
      baseKey: Buffer.alloc(33, 1),
      identityKey: Buffer.alloc(33, 2),
      message: Buffer.alloc(64, 3)
    })
    const encoded = protobufs.PreKeyWhisperMessage.encode(message).finish()
    const decoded = protobufs.PreKeyWhisperMessage.decode(encoded)
    assert.equal(decoded.registrationId, 10)
    assert.equal(decoded.preKeyId, 2)
    assert.equal(decoded.signedPreKeyId, 3)
    assert.deepEqual(Buffer.from(decoded.baseKey), Buffer.alloc(33, 1))
  })

  it("is byte-compatible with WhisperTextProtocol.proto", () => {
    const output = execFileSync(process.execPath, [join(rootDir, "scripts", "verify-proto.mjs")], {
      cwd: rootDir,
      encoding: "utf-8"
    })
    assert.match(output, /WhisperMessage: OK/)
    assert.match(output, /PreKeyWhisperMessage: OK/)
    assert.match(output, /KeyExchangeMessage: OK/)
  })
})
