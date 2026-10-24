import {
  FileSignalStorage,
  MemorySignalStorage,
  ProtocolAddress,
  SessionBuilder,
  SessionCipher,
  keyhelper
} from "../lib/index.js"

export class Party {
  constructor(identifier, storage, identity, registrationId) {
    this.identifier = identifier
    this.storage = storage
    this.identity = identity
    this.registrationId = registrationId
    this.signedPreKeys = new Map()
    this.preKeys = new Map()
  }

  addSignedPreKey(keyId, record = keyhelper.generateSignedPreKey(this.identity, keyId)) {
    this.signedPreKeys.set(keyId, record)
    this.storage.storeSignedPreKey(record)
    return record
  }

  addPreKey(keyId, record = keyhelper.generatePreKey(keyId)) {
    this.preKeys.set(keyId, record)
    this.storage.storePreKey(keyId, record.keyPair)
    return record
  }

  bundle({ preKeyId = 1, signedPreKeyId = 1 } = {}) {
    const signed = this.signedPreKeys.get(signedPreKeyId)
    const preKey = this.preKeys.get(preKeyId)
    if (!signed) {
      throw new Error(`Missing signed prekey ${signedPreKeyId}`)
    }

    return {
      registrationId: this.registrationId,
      identityKey: this.identity.pubKey,
      signedPreKey: {
        keyId: signed.keyId,
        publicKey: signed.keyPair.pubKey,
        signature: signed.signature
      },
      ...(preKey ? { preKey: { keyId: preKey.keyId, publicKey: preKey.keyPair.pubKey } } : {})
    }
  }

  address(deviceId = 1) {
    return new ProtocolAddress(this.identifier, deviceId)
  }

  builderFor(remoteIdentifier, deviceId = 1) {
    return new SessionBuilder(this.storage, new ProtocolAddress(remoteIdentifier, deviceId))
  }

  cipherFor(remoteIdentifier, deviceId = 1, staleSessionMaxAgeMs) {
    return new SessionCipher(this.storage, new ProtocolAddress(remoteIdentifier, deviceId), staleSessionMaxAgeMs)
  }
}

export function createMemoryParty(identifier) {
  return createMemoryPartyWithIdentity(identifier, keyhelper.generateIdentityKeyPair())
}

export function createMemoryPartyWithIdentity(identifier, identity) {
  const registrationId = keyhelper.generateRegistrationId()
  const storage = new MemorySignalStorage(identity, registrationId)
  return new Party(identifier, storage, identity, registrationId)
}

export async function createFileParty(identifier, filePath, options = {}) {
  const storage = FileSignalStorage.create(filePath, options)
  const identity = await storage.getOurIdentity()
  const registrationId = await storage.getOurRegistrationId()
  return new Party(identifier, storage, identity, registrationId)
}

export async function establishSession(sender, recipient, options = {}) {
  await sender.builderFor(recipient.identifier).initOutgoing(recipient.bundle(options))
  return {
    senderCipher: sender.cipherFor(recipient.identifier),
    recipientCipher: recipient.cipherFor(sender.identifier)
  }
}

export function flipByte(buffer, index = 0) {
  const copy = Buffer.from(buffer)
  copy[index] ^= 0xff
  return copy
}
