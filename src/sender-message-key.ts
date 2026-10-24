import * as crypto from "./crypto"
import { wipeBuffer } from "./util"

export class SenderMessageKey {
  private readonly iteration: number
  private readonly iv: Buffer
  private readonly cipherKey: Buffer
  private readonly seed: Buffer

  constructor(iteration: number, seed: Uint8Array) {
    const derivative = crypto.deriveSecrets(seed, Buffer.alloc(32), Buffer.from("WhisperGroup"))
    const part0 = derivative[0]
    const part1 = derivative[1]

    if (!part0 || !part1) {
      throw new Error("Failed to derive sender message key material")
    }

    this.iv = Buffer.from(part0.subarray(0, 16))
    this.cipherKey = Buffer.concat([part0.subarray(16), part1.subarray(0, 16)])
    this.iteration = iteration
    this.seed = Buffer.from(seed)

    wipeBuffer(part0)
    wipeBuffer(part1)
  }

  public getIteration(): number {
    return this.iteration
  }

  public getIv(): Buffer {
    return this.iv
  }

  public getCipherKey(): Buffer {
    return this.cipherKey
  }

  public getSeed(): Buffer {
    return this.seed
  }
}
