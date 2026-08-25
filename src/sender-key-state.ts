import { SenderChainKey } from "./sender-chain-key"
import { SenderMessageKey } from "./sender-message-key"

const MAX_MESSAGE_KEYS = 2000

interface SenderChainKeyStructure {
  iteration: number
  seed: Buffer
}

interface SenderSigningKeyStructure {
  public: Buffer
  private?: Buffer
}

interface SenderMessageKeyStructure {
  iteration: number
  seed: Buffer
}

export interface SerializedSenderChainKey {
  iteration: number
  seed: string
}

export interface SerializedSenderMessageKey {
  iteration: number
  seed: string
}

export interface SerializedSenderSigningKey {
  public: string
  private?: string
}

export interface SerializedSenderKeyState {
  senderKeyId: number
  senderChainKey: SerializedSenderChainKey
  senderSigningKey: SerializedSenderSigningKey
  senderMessageKeys: SerializedSenderMessageKey[]
}

export class SenderKeyState {
  private senderKeyId: number
  private senderChainKey: SenderChainKeyStructure
  private readonly senderSigningKey: SenderSigningKeyStructure
  private senderMessageKeys: SenderMessageKeyStructure[]

  constructor(
    id: number,
    iteration: number,
    chainKey: Uint8Array,
    signingKeyPublic: Uint8Array,
    signingKeyPrivate?: Uint8Array
  ) {
    this.senderKeyId = id
    this.senderChainKey = { iteration, seed: Buffer.from(chainKey) }
    this.senderSigningKey = {
      public: Buffer.from(signingKeyPublic),
      private: signingKeyPrivate ? Buffer.from(signingKeyPrivate) : undefined
    }
    this.senderMessageKeys = []
  }

  public getKeyId(): number {
    return this.senderKeyId
  }

  public getSenderChainKey(): SenderChainKey {
    return new SenderChainKey(this.senderChainKey.iteration, this.senderChainKey.seed)
  }

  public setSenderChainKey(chainKey: SenderChainKey): void {
    this.senderChainKey = { iteration: chainKey.getIteration(), seed: chainKey.getSeed() }
  }

  public getSigningKeyPublic(): Buffer {
    return this.senderSigningKey.public
  }

  public getSigningKeyPrivate(): Buffer | undefined {
    return this.senderSigningKey.private
  }

  public hasSenderMessageKey(iteration: number): boolean {
    return this.senderMessageKeys.some((key) => key.iteration === iteration)
  }

  public addSenderMessageKey(senderMessageKey: SenderMessageKey): void {
    this.senderMessageKeys.push({
      iteration: senderMessageKey.getIteration(),
      seed: senderMessageKey.getSeed()
    })

    if (this.senderMessageKeys.length > MAX_MESSAGE_KEYS) {
      this.senderMessageKeys.shift()
    }
  }

  public removeSenderMessageKey(iteration: number): SenderMessageKey | undefined {
    const index = this.senderMessageKeys.findIndex((key) => key.iteration === iteration)

    if (index === -1) {
      return undefined
    }

    const messageKey = this.senderMessageKeys[index]
    if (!messageKey) {
      return undefined
    }

    this.senderMessageKeys.splice(index, 1)
    return new SenderMessageKey(messageKey.iteration, messageKey.seed)
  }

  public serialize(): SerializedSenderKeyState {
    return {
      senderKeyId: this.senderKeyId,
      senderChainKey: {
        iteration: this.senderChainKey.iteration,
        seed: this.senderChainKey.seed.toString("base64")
      },
      senderSigningKey: {
        public: this.senderSigningKey.public.toString("base64"),
        private: this.senderSigningKey.private?.toString("base64")
      },
      senderMessageKeys: this.senderMessageKeys.map((key) => ({
        iteration: key.iteration,
        seed: key.seed.toString("base64")
      }))
    }
  }

  static deserialize(data: SerializedSenderKeyState): SenderKeyState {
    const state = new SenderKeyState(
      data.senderKeyId,
      data.senderChainKey.iteration,
      Buffer.from(data.senderChainKey.seed, "base64"),
      Buffer.from(data.senderSigningKey.public, "base64"),
      data.senderSigningKey.private ? Buffer.from(data.senderSigningKey.private, "base64") : undefined
    )

    state.senderMessageKeys = data.senderMessageKeys.map((key) => ({
      iteration: key.iteration,
      seed: Buffer.from(key.seed, "base64")
    }))

    return state
  }
}
