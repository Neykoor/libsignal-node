import { SenderKeyError } from "./errors"
import * as groupKeyHelper from "./group-keyhelper"
import { SenderKeyDistributionMessage } from "./sender-key-distribution-message"
import type { SenderKeyName } from "./sender-key-name"
import { SenderKeyRecord } from "./sender-key-record"
import type { SenderKeyStore } from "./types"

export class GroupSessionBuilder {
  private readonly senderKeyStore: SenderKeyStore

  constructor(senderKeyStore: SenderKeyStore) {
    this.senderKeyStore = senderKeyStore
  }

  /**
   * Procesa un SenderKeyDistributionMessage recibido de otro miembro del grupo
   * y guarda su sender key state para poder descifrar sus mensajes.
   */
  async process(
    senderKeyName: SenderKeyName,
    senderKeyDistributionMessage: SenderKeyDistributionMessage
  ): Promise<void> {
    const senderKeyRecord = (await this.senderKeyStore.loadSenderKey(senderKeyName)) ?? new SenderKeyRecord()

    senderKeyRecord.addSenderKeyState(
      senderKeyDistributionMessage.getId(),
      senderKeyDistributionMessage.getIteration(),
      senderKeyDistributionMessage.getChainKey(),
      senderKeyDistributionMessage.getSignatureKey()
    )

    await this.senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord)
  }

  /**
   * Crea (o reutiliza) nuestra propia sender key para el grupo y devuelve el
   * SenderKeyDistributionMessage que hay que enviar al resto de miembros.
   */
  async create(senderKeyName: SenderKeyName): Promise<SenderKeyDistributionMessage> {
    const senderKeyRecord = (await this.senderKeyStore.loadSenderKey(senderKeyName)) ?? new SenderKeyRecord()

    if (senderKeyRecord.isEmpty()) {
      const keyId = groupKeyHelper.generateSenderKeyId()
      const senderKey = groupKeyHelper.generateSenderKey()
      const signingKey = groupKeyHelper.generateSenderSigningKey()

      senderKeyRecord.addSenderKeyState(keyId, 0, senderKey, signingKey.pubKey, signingKey.privKey)
    }

    await this.senderKeyStore.storeSenderKey(senderKeyName, senderKeyRecord)

    const state = senderKeyRecord.getSenderKeyState()
    if (!state) {
      throw new SenderKeyError("Failed to create sender key state")
    }

    const chainKey = state.getSenderChainKey()

    return new SenderKeyDistributionMessage(
      state.getKeyId(),
      chainKey.getIteration(),
      chainKey.getSeed(),
      state.getSigningKeyPublic()
    )
  }
}
