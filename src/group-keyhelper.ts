import * as nodeCrypto from "crypto"
import * as curve from "./curve"
import type { KeyPair } from "./curve"

export function generateSenderKey(): Buffer {
  return nodeCrypto.randomBytes(32)
}

export function generateSenderKeyId(): number {
  return nodeCrypto.randomBytes(4).readUInt32BE(0)
}

export function generateSenderSigningKey(keyPair?: KeyPair): KeyPair {
  return keyPair ?? curve.generateKeyPair()
}
