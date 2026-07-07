import { BaseKeyType } from './base-key-type'
import { ChainType } from './chain-type'
import * as crypto from './crypto'
import * as curve from './curve'
import type { KeyPair } from './curve'
import * as errors from './errors'
import type { ProtocolAddress } from './protocol-address'
import { queueJob } from './queue-job'
import { SessionEntry, SessionRecord } from './session-record'
import type { DeviceKeyBundle, IncomingPreKeyMessage, SignalStorage } from './types'

export class SessionBuilder {
	private addr: ProtocolAddress
	private storage: SignalStorage

	constructor(storage: SignalStorage, protocolAddress: ProtocolAddress) {
		this.addr = protocolAddress
		this.storage = storage
	}

	async initOutgoing(device: DeviceKeyBundle): Promise<void> {
		const fqAddr = this.addr.toString()
		return await queueJob(fqAddr, async () => {
			if (!(await this.storage.isTrustedIdentity(this.addr.id, device.identityKey))) {
				throw new errors.UntrustedIdentityKeyError(this.addr.id, device.identityKey)
			}

			if (!curve.verifySignature(device.identityKey, device.signedPreKey.publicKey, device.signedPreKey.signature)) {
				throw new Error('Signature validation failed')
			}

			const baseKey = curve.generateKeyPair()
			const devicePreKey = device.preKey && device.preKey.publicKey
			const session = await this.initSession(
				true,
				baseKey,
				undefined,
				device.identityKey,
				devicePreKey,
				device.signedPreKey.publicKey,
				device.registrationId
			)
			session.pendingPreKey = {
				signedKeyId: device.signedPreKey.keyId,
				baseKey: baseKey.pubKey
			}

			if (device.preKey) {
				session.pendingPreKey.preKeyId = device.preKey.keyId
			}

			let record = await this.storage.loadSession(fqAddr)
			if (!record) {
				record = new SessionRecord()
			} else {
				const openSession = record.getOpenSession()
				if (openSession) {
					record.closeSession(openSession)
				}
			}

			record.setSession(session)
			record.removeOldSessions()
			await this.storage.storeSession(fqAddr, record)
		})
	}

	async initIncoming(record: SessionRecord, message: IncomingPreKeyMessage): Promise<number | undefined> {
		if (!(await this.storage.isTrustedIdentity(this.addr.id, message.identityKey))) {
			throw new errors.UntrustedIdentityKeyError(this.addr.id, message.identityKey)
		}

		if (record.getSession(message.baseKey)) {
			return undefined
		}

		const preKeyPair = await this.storage.loadPreKey(message.preKeyId)
		if (message.preKeyId && !preKeyPair) {
			throw new errors.PreKeyError('Invalid PreKey ID')
		}

		const signedPreKeyPair = await this.storage.loadSignedPreKey(message.signedPreKeyId)
		if (!signedPreKeyPair) {
			throw new errors.PreKeyError('Missing SignedPreKey')
		}

		const existingOpenSession = record.getOpenSession()
		if (existingOpenSession) {
			record.closeSession(existingOpenSession)
		}

		record.setSession(
			await this.initSession(
				false,
				preKeyPair,
				signedPreKeyPair,
				message.identityKey,
				message.baseKey,
				undefined,
				message.registrationId
			)
		)

		return message.preKeyId
	}

	private async initSession(
		isInitiator: boolean,
		ourEphemeralKey: KeyPair | undefined,
		ourSignedKeyInput: KeyPair | undefined,
		theirIdentityPubKey: Buffer,
		theirEphemeralPubKey: Buffer | undefined,
		theirSignedPubKeyInput: Buffer | undefined,
		registrationId: number | undefined
	): Promise<SessionEntry> {
		let ourSignedKey = ourSignedKeyInput
		let theirSignedPubKey = theirSignedPubKeyInput

		if (isInitiator) {
			if (ourSignedKey) {
				throw new Error('Invalid call to initSession')
			}

			ourSignedKey = ourEphemeralKey
		} else {
			if (theirSignedPubKey) {
				throw new Error('Invalid call to initSession')
			}

			theirSignedPubKey = theirEphemeralPubKey
		}

		let sharedSecret: Uint8Array
		if (!ourEphemeralKey || !theirEphemeralPubKey) {
			sharedSecret = new Uint8Array(32 * 4)
		} else {
			sharedSecret = new Uint8Array(32 * 5)
		}

		for (let i = 0; i < 32; i++) {
			sharedSecret[i] = 0xff
		}

		const ourIdentityKey = await this.storage.getOurIdentity()
		const a1 = curve.calculateAgreement(theirSignedPubKey!, ourIdentityKey.privKey)
		const a2 = curve.calculateAgreement(theirIdentityPubKey, ourSignedKey!.privKey)
		const a3 = curve.calculateAgreement(theirSignedPubKey!, ourSignedKey!.privKey)

		if (isInitiator) {
			sharedSecret.set(new Uint8Array(a1), 32)
			sharedSecret.set(new Uint8Array(a2), 32 * 2)
		} else {
			sharedSecret.set(new Uint8Array(a1), 32 * 2)
			sharedSecret.set(new Uint8Array(a2), 32)
		}

		sharedSecret.set(new Uint8Array(a3), 32 * 3)

		if (ourEphemeralKey && theirEphemeralPubKey) {
			const a4 = curve.calculateAgreement(theirEphemeralPubKey, ourEphemeralKey.privKey)
			sharedSecret.set(new Uint8Array(a4), 32 * 4)
		}

		const masterKey = crypto.deriveSecrets(Buffer.from(sharedSecret), Buffer.alloc(32), Buffer.from('WhisperText'))

		const session = SessionRecord.createEntry()
		session.registrationId = registrationId
		session.currentRatchet = {
			rootKey: masterKey[0]!,
			ephemeralKeyPair: isInitiator ? curve.generateKeyPair() : ourSignedKey!,
			lastRemoteEphemeralKey: theirSignedPubKey!,
			previousCounter: 0
		}
		session.indexInfo = {
			created: Date.now(),
			used: Date.now(),
			remoteIdentityKey: theirIdentityPubKey,
			baseKey: isInitiator ? ourEphemeralKey!.pubKey : theirEphemeralPubKey!,
			baseKeyType: isInitiator ? BaseKeyType.OURS : BaseKeyType.THEIRS,
			closed: -1
		}

		if (isInitiator) {
			this.calculateSendingRatchet(session, theirSignedPubKey!)
		}

		return session
	}

	private calculateSendingRatchet(session: SessionEntry, remoteKey: Buffer): void {
		const ratchet = session.currentRatchet
		const sharedSecret = curve.calculateAgreement(remoteKey, ratchet.ephemeralKeyPair.privKey)
		const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey, Buffer.from('WhisperRatchet'))

		session.addChain(ratchet.ephemeralKeyPair.pubKey, {
			messageKeys: {},
			chainKey: {
				counter: -1,
				key: masterKey[1]
			},
			chainType: ChainType.SENDING
		})

		ratchet.rootKey = masterKey[0]!
	}
}
