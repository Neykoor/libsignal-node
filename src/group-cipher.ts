import * as crypto from "./crypto"
import { SenderKeyError } from "./errors"
import { queueJob } from "./queue-job"
import type { SenderKeyName } from "./sender-key-name"
import { SenderKeyMessage } from "./sender-key-message"
import type { SenderKeyState } from "./sender-key-state"
import type { SenderMessageKey } from "./sender-message-key"
import type { SenderKeyStore } from "./types"
import { wipeBuffer } from "./util"

const MAX_JUMP = 2000

export class GroupCipher {
  private readonly senderKeyStore: SenderKeyStore
  private readonly senderKeyName: SenderKeyName

  constructor(senderKeyStore: SenderKeyStore, senderKeyName: SenderKeyName) {
    this.senderKeyStore = senderKeyStore
    this.senderKeyName = senderKeyName
  }

  private async queueJob<T>(awaitable: () => Promise<T>): Promise<T> {
    return await queueJob(this.senderKeyName.toString(), awaitable)
  }

  async encrypt(paddedPlaintext: Uint8Array): Promise<Buffer> {
    return await this.queueJob(async () => {
      const record = await this.senderKeyStore.loadSenderKey(this.senderKeyName)
      if (!record) {
        throw new SenderKeyError("No SenderKeyRecord found for encryption")
      }

      const senderKeyState = record.getSenderKeyState()
      if (!senderKeyState) {
        throw new SenderKeyError("No session to encrypt message")
      }

      const signingKeyPrivate = senderKeyState.getSigningKeyPrivate()
      if (!signingKeyPrivate) {
        throw new SenderKeyError("Signing key is not available for encryption")
      }

      const iteration = senderKeyState.getSenderChainKey().getIteration()
      const senderKey = this.getSenderKey(senderKeyState, iteration === 0 ? 0 : iteration + 1)

      const ciphertext = crypto.encrypt(senderKey.getCipherKey(), Buffer.from(paddedPlaintext), senderKey.getIv())

      const senderKeyMessage = new SenderKeyMessage(
        senderKeyState.getKeyId(),
        senderKey.getIteration(),
        ciphertext,
        signingKeyPrivate
      )

      wipeBuffer(senderKey.getCipherKey())
      wipeBuffer(senderKey.getIv())

      await this.senderKeyStore.storeSenderKey(this.senderKeyName, record)
      return senderKeyMessage.serialize()
    })
  }

  async decrypt(senderKeyMessageBytes: Uint8Array): Promise<Buffer> {
    return await this.queueJob(async () => {
      const record = await this.senderKeyStore.loadSenderKey(this.senderKeyName)
      if (!record) {
        throw new SenderKeyError("No sender key record found for decryption")
      }

      const senderKeyMessage = new SenderKeyMessage(undefined, undefined, undefined, undefined, senderKeyMessageBytes)
      const senderKeyState = record.getSenderKeyState(senderKeyMessage.getKeyId())

      if (!senderKeyState) {
        throw new SenderKeyError(
          `No session found to decrypt message from ${this.senderKeyName.getSender().toString()} with keyId: ${senderKeyMessage.getKeyId()}`
        )
      }

      senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic())

      const senderKey = this.getSenderKey(senderKeyState, senderKeyMessage.getIteration())
      const plaintext = crypto.decrypt(senderKey.getCipherKey(), senderKeyMessage.getCipherText(), senderKey.getIv())

      wipeBuffer(senderKey.getCipherKey())
      wipeBuffer(senderKey.getIv())

      await this.senderKeyStore.storeSenderKey(this.senderKeyName, record)
      return plaintext
    })
  }

  private getSenderKey(senderKeyState: SenderKeyState, iteration: number): SenderMessageKey {
    let senderChainKey = senderKeyState.getSenderChainKey()

    if (senderChainKey.getIteration() > iteration) {
      if (senderKeyState.hasSenderMessageKey(iteration)) {
        return senderKeyState.removeSenderMessageKey(iteration)!
      }

      throw new SenderKeyError(`Received message with old counter: ${senderChainKey.getIteration()} , ${iteration}`)
    }

    if (iteration - senderChainKey.getIteration() > MAX_JUMP) {
      throw new SenderKeyError("Over 2000 messages into the future!")
    }

    while (senderChainKey.getIteration() < iteration) {
      senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey())
      senderChainKey = senderChainKey.getNext()
    }

    senderKeyState.setSenderChainKey(senderChainKey)
    return senderChainKey.getSenderMessageKey()
  }
}
