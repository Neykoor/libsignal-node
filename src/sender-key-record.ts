import { SenderKeyState } from "./sender-key-state"
import type { SerializedSenderKeyState } from "./sender-key-state"

const MAX_STATES = 5

export type SerializedSenderKeyRecord = SerializedSenderKeyState[]

export class SenderKeyRecord {
  private readonly senderKeyStates: SenderKeyState[] = []

  public isEmpty(): boolean {
    return this.senderKeyStates.length === 0
  }

  public getSenderKeyState(keyId?: number): SenderKeyState | undefined {
    if (keyId === undefined) {
      return this.senderKeyStates[this.senderKeyStates.length - 1]
    }

    return this.senderKeyStates.find((state) => state.getKeyId() === keyId)
  }

  public addSenderKeyState(
    id: number,
    iteration: number,
    chainKey: Uint8Array,
    signingKeyPublic: Uint8Array,
    signingKeyPrivate?: Uint8Array
  ): void {
    this.senderKeyStates.push(new SenderKeyState(id, iteration, chainKey, signingKeyPublic, signingKeyPrivate))

    if (this.senderKeyStates.length > MAX_STATES) {
      this.senderKeyStates.shift()
    }
  }

  public setSenderKeyState(
    id: number,
    iteration: number,
    chainKey: Uint8Array,
    signingKeyPublic: Uint8Array,
    signingKeyPrivate?: Uint8Array
  ): void {
    this.senderKeyStates.length = 0
    this.senderKeyStates.push(new SenderKeyState(id, iteration, chainKey, signingKeyPublic, signingKeyPrivate))
  }

  public serialize(): SerializedSenderKeyRecord {
    return this.senderKeyStates.map((state) => state.serialize())
  }

  static deserialize(data: SerializedSenderKeyRecord): SenderKeyRecord {
    const record = new SenderKeyRecord()

    for (const structure of data) {
      record.senderKeyStates.push(SenderKeyState.deserialize(structure))
    }

    return record
  }
}
