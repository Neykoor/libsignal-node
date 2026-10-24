import { CiphertextMessage } from "./ciphertext-message"
import * as curve from "./curve"
import { SenderKeyMessageProto } from "./group-proto"

const SIGNATURE_LENGTH = 64

export class SenderKeyMessage extends CiphertextMessage {
  private readonly messageVersion: number
  private readonly keyId: number
  private readonly iteration: number
  private readonly ciphertext: Buffer
  private readonly signature: Buffer
  private readonly serialized: Buffer

  constructor(
    keyId?: number,
    iteration?: number,
    ciphertext?: Uint8Array,
    signatureKey?: Uint8Array,
    serialized?: Uint8Array
  ) {
    super()

    if (serialized) {
      const buf = Buffer.from(serialized)
      const versionByte = buf[0]

      if (versionByte === undefined || buf.length <= SIGNATURE_LENGTH) {
        throw new Error("Invalid SenderKeyMessage: too short")
      }

      const message = buf.subarray(1, buf.length - SIGNATURE_LENGTH)
      const signature = buf.subarray(buf.length - SIGNATURE_LENGTH)
      const senderKeyMessage = SenderKeyMessageProto.decode(message)

      this.serialized = buf
      this.messageVersion = (versionByte & 0xff) >> 4
      this.keyId = senderKeyMessage.id
      this.iteration = senderKeyMessage.iteration
      this.ciphertext = Buffer.from(senderKeyMessage.ciphertext)
      this.signature = Buffer.from(signature)
      return
    }

    if (keyId === undefined || iteration === undefined || !ciphertext || !signatureKey) {
      throw new Error("Missing arguments to build a new SenderKeyMessage")
    }

    const version = (((this.CURRENT_VERSION << 4) | this.CURRENT_VERSION) & 0xff) % 256
    const ciphertextBuffer = Buffer.from(ciphertext)
    const message = Buffer.from(
      SenderKeyMessageProto.encode(
        SenderKeyMessageProto.create({
          id: keyId,
          iteration,
          ciphertext: ciphertextBuffer
        })
      )
    )

    const signature = curve.calculateSignature(signatureKey, Buffer.concat([Buffer.from([version]), message]))

    this.serialized = Buffer.concat([Buffer.from([version]), message, signature])
    this.messageVersion = this.CURRENT_VERSION
    this.keyId = keyId
    this.iteration = iteration
    this.ciphertext = ciphertextBuffer
    this.signature = signature
  }

  public getKeyId(): number {
    return this.keyId
  }

  public getIteration(): number {
    return this.iteration
  }

  public getCipherText(): Buffer {
    return this.ciphertext
  }

  public verifySignature(signatureKey: Uint8Array): void {
    const part1 = this.serialized.subarray(0, this.serialized.length - SIGNATURE_LENGTH)
    const part2 = this.serialized.subarray(this.serialized.length - SIGNATURE_LENGTH)

    if (!curve.verifySignature(signatureKey, part1, part2)) {
      throw new Error("Invalid signature!")
    }
  }

  public serialize(): Buffer {
    return this.serialized
  }

  public getType(): number {
    return this.SENDERKEY_TYPE
  }
}
