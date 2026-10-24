import { CiphertextMessage } from "./ciphertext-message"
import { SenderKeyDistributionMessageProto } from "./group-proto"

export class SenderKeyDistributionMessage extends CiphertextMessage {
  private readonly id: number
  private readonly iteration: number
  private readonly chainKey: Buffer
  private readonly signatureKey: Buffer
  private readonly serialized: Buffer

  constructor(
    id?: number,
    iteration?: number,
    chainKey?: Uint8Array,
    signatureKey?: Uint8Array,
    serialized?: Uint8Array
  ) {
    super()

    if (serialized) {
      const buf = Buffer.from(serialized)

      try {
        const distributionMessage = SenderKeyDistributionMessageProto.decode(buf.subarray(1))

        this.serialized = buf
        this.id = distributionMessage.id
        this.iteration = distributionMessage.iteration
        this.chainKey = Buffer.from(distributionMessage.chainKey)
        this.signatureKey = Buffer.from(distributionMessage.signingKey)
      } catch (e) {
        const reason = e instanceof Error ? e.message : String(e)
        throw new Error(`Failed to decode SenderKeyDistributionMessage: ${reason}`)
      }

      return
    }

    if (id === undefined || iteration === undefined || !chainKey || !signatureKey) {
      throw new Error("Missing arguments to build a new SenderKeyDistributionMessage")
    }

    const version = (((this.CURRENT_VERSION << 4) | this.CURRENT_VERSION) & 0xff) % 256

    this.id = id
    this.iteration = iteration
    this.chainKey = Buffer.from(chainKey)
    this.signatureKey = Buffer.from(signatureKey)

    const message = Buffer.from(
      SenderKeyDistributionMessageProto.encode(
        SenderKeyDistributionMessageProto.create({
          id,
          iteration,
          chainKey: this.chainKey,
          signingKey: this.signatureKey
        })
      )
    )

    this.serialized = Buffer.concat([Buffer.from([version]), message])
  }

  public serialize(): Buffer {
    return this.serialized
  }

  public getType(): number {
    return this.SENDERKEY_DISTRIBUTION_TYPE
  }

  public getIteration(): number {
    return this.iteration
  }

  public getChainKey(): Buffer {
    return this.chainKey
  }

  public getSignatureKey(): Buffer {
    return this.signatureKey
  }

  public getId(): number {
    return this.id
  }
}
