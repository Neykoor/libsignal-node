import * as crypto from "./crypto"
import { SenderMessageKey } from "./sender-message-key"

const MESSAGE_KEY_SEED = Buffer.from([0x01])
const CHAIN_KEY_SEED = Buffer.from([0x02])

export class SenderChainKey {
  private readonly iteration: number
  private readonly chainKey: Buffer

  constructor(iteration: number, chainKey: Uint8Array | string) {
    this.iteration = iteration
    this.chainKey = typeof chainKey === "string" ? Buffer.from(chainKey, "base64") : Buffer.from(chainKey)
  }

  public getIteration(): number {
    return this.iteration
  }

  public getSenderMessageKey(): SenderMessageKey {
    return new SenderMessageKey(this.iteration, this.getDerivative(MESSAGE_KEY_SEED, this.chainKey))
  }

  public getNext(): SenderChainKey {
    return new SenderChainKey(this.iteration + 1, this.getDerivative(CHAIN_KEY_SEED, this.chainKey))
  }

  public getSeed(): Buffer {
    return this.chainKey
  }

  private getDerivative(seed: Uint8Array, key: Buffer): Buffer {
    return crypto.calculateMAC(key, seed)
  }
}
