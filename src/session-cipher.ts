import { ChainType } from './chain-type'
import * as crypto from './crypto'
import * as curve from './curve'
import * as errors from './errors'
import { ProtocolAddress } from './protocol-address'
import * as protobufs from './protobufs'
import { queueJob } from './queue-job'
import { wipeBuffer } from './util'
import { SessionBuilder } from './session-builder'
import type { Chain, SessionEntry } from './session-record'
import { SessionRecord } from './session-record'
import type { EncryptedMessage, SignalStorage } from './types'

const VERSION = 3

function assertBuffer(value: unknown): Uint8Array {
	if (!(value instanceof Uint8Array)) {
		throw TypeError(`Expected Uint8Array instead of: ${(value as unknown as object)?.constructor?.name}`)
	}

	return value
}

export class SessionCipher {
	private addr: ProtocolAddress
	private storage: SignalStorage

	constructor(storage: SignalStorage, protocolAddress: ProtocolAddress) {
		if (!(protocolAddress instanceof ProtocolAddress)) {
			throw new TypeError('protocolAddress must be a ProtocolAddress')
		}

		this.addr = protocolAddress
		this.storage = storage
	}

	private _encodeTupleByte(number1: number, number2: number): number {
		if (number1 > 15 || number2 > 15) {
			throw TypeError('Numbers must be 4 bits or less')
		}

		return (number1 << 4) | number2
	}

	private _decodeTupleByte(byte: number): [number, number] {
		return [byte >> 4, byte & 0xf]
	}

	toString(): string {
		return `<SessionCipher(${this.addr.toString()})>`
	}

	async getRecord(): Promise<SessionRecord | undefined> {
		const record = await this.storage.loadSession(this.addr.toString())
		if (record && !(record instanceof SessionRecord)) {
			throw new TypeError('SessionRecord type expected from loadSession')
		}

		return record
	}

	async storeRecord(record: SessionRecord): Promise<void> {
		record.removeOldSessions()
		await this.storage.storeSession(this.addr.toString(), record)
	}

	async queueJob<T>(awaitable: () => Promise<T>): Promise<T> {
		return await queueJob(this.addr.toString(), awaitable)
	}

	async encrypt(data: Uint8Array): Promise<EncryptedMessage> {
		assertBuffer(data)
		const ourIdentityKey = await this.storage.getOurIdentity()

		return await this.queueJob(async () => {
			const record = await this.getRecord()
			if (!record) {
				throw new errors.SessionError('No sessions')
			}

			const session = record.getOpenSession()
			if (!session) {
				throw new errors.SessionError('No open session')
			}

			const remoteIdentityKey = session.indexInfo.remoteIdentityKey
			if (!(await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey))) {
				throw new errors.UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey)
			}

			const chain = session.getChain(session.currentRatchet.ephemeralKeyPair.pubKey)
			if (!chain) {
				throw new errors.SessionError('No chain found for current ratchet')
			}

			if (chain.chainType === ChainType.RECEIVING) {
				throw new Error('Tried to encrypt on a receiving chain')
			}

			this.fillMessageKeys(chain, chain.chainKey.counter + 1)
			const keys = crypto.deriveSecrets(
				chain.messageKeys[chain.chainKey.counter]!,
				Buffer.alloc(32),
				Buffer.from('WhisperMessageKeys')
			)
			wipeBuffer(chain.messageKeys[chain.chainKey.counter])
			delete chain.messageKeys[chain.chainKey.counter]

			const msg = protobufs.WhisperMessage.create()
			msg.ephemeralKey = session.currentRatchet.ephemeralKeyPair.pubKey
			msg.counter = chain.chainKey.counter
			msg.previousCounter = session.currentRatchet.previousCounter
			msg.ciphertext = crypto.encrypt(keys[0]!, data, keys[2]!.slice(0, 16))

			const msgBuf = protobufs.WhisperMessage.encode(msg).finish()
			const macInput = Buffer.alloc(msgBuf.byteLength + 33 * 2 + 1)
			macInput.set(ourIdentityKey.pubKey)
			macInput.set(session.indexInfo.remoteIdentityKey, 33)
			macInput[33 * 2] = this._encodeTupleByte(VERSION, VERSION)
			macInput.set(msgBuf, 33 * 2 + 1)

			const mac = crypto.calculateMAC(keys[1]!, macInput)
			const result = Buffer.alloc(msgBuf.byteLength + 9)
			result[0] = this._encodeTupleByte(VERSION, VERSION)
			result.set(msgBuf, 1)
			result.set(mac.slice(0, 8), msgBuf.byteLength + 1)

			await this.storeRecord(record)

			let type: number
			let body: Buffer

			if (session.pendingPreKey) {
				type = 3
				const preKeyMsg = protobufs.PreKeyWhisperMessage.create({
					identityKey: ourIdentityKey.pubKey,
					registrationId: await this.storage.getOurRegistrationId(),
					baseKey: session.pendingPreKey.baseKey,
					signedPreKeyId: session.pendingPreKey.signedKeyId,
					message: result
				})

				if (session.pendingPreKey.preKeyId) {
					preKeyMsg.preKeyId = session.pendingPreKey.preKeyId
				}

				body = Buffer.concat([
					Buffer.from([this._encodeTupleByte(VERSION, VERSION)]),
					Buffer.from(protobufs.PreKeyWhisperMessage.encode(preKeyMsg).finish())
				])
			} else {
				type = 1
				body = result
			}

			return {
				type,
				body,
				registrationId: session.registrationId
			}
		})
	}

	async decryptWithSessions(
		data: Uint8Array,
		sessions: SessionEntry[]
	): Promise<{ session: SessionEntry; plaintext: Buffer }> {
		if (!sessions.length) {
			throw new errors.SessionError('No sessions available')
		}

		const errs: unknown[] = []
		for (const session of sessions) {
			let plaintext: Buffer
			try {
				plaintext = await this.doDecryptWhisperMessage(data, session)
				session.indexInfo.used = Date.now()
				return {
					session,
					plaintext
				}
			} catch (e) {
				errs.push(e)
			}
		}

		throw new errors.SessionError('No matching sessions found for message')
	}

	async decryptWhisperMessage(data: Uint8Array): Promise<Buffer> {
		assertBuffer(data)
		return await this.queueJob(async () => {
			const record = await this.getRecord()
			if (!record) {
				throw new errors.SessionError('No session record')
			}

			const result = await this.decryptWithSessions(data, record.getSessions())
			const remoteIdentityKey = result.session.indexInfo.remoteIdentityKey
			if (!(await this.storage.isTrustedIdentity(this.addr.id, remoteIdentityKey))) {
				throw new errors.UntrustedIdentityKeyError(this.addr.id, remoteIdentityKey)
			}

			if (record.isClosed(result.session)) {
				result.session.indexInfo.used = Date.now()
			}

			await this.storeRecord(record)
			return result.plaintext
		})
	}

	async decryptPreKeyWhisperMessage(data: Uint8Array): Promise<Buffer> {
		assertBuffer(data)
		const versions = this._decodeTupleByte(data[0]!)
		if (versions[1] > 3 || versions[0] < 3) {
			throw new Error('Incompatible version number on PreKeyWhisperMessage')
		}

		return await this.queueJob(async () => {
			let record = await this.getRecord()
			const preKeyProto = protobufs.PreKeyWhisperMessage.decode(data.slice(1))

			if (!record) {
				if (preKeyProto.registrationId == null) {
					throw new Error('No registrationId')
				}

				record = new SessionRecord()
			}

			const builder = new SessionBuilder(this.storage, this.addr)
			const preKeyId = await builder.initIncoming(record, {
				registrationId: preKeyProto.registrationId,
				identityKey: Buffer.from(preKeyProto.identityKey),
				baseKey: Buffer.from(preKeyProto.baseKey),
				preKeyId: preKeyProto.preKeyId,
				signedPreKeyId: preKeyProto.signedPreKeyId,
				message: Buffer.from(preKeyProto.message)
			})

			const session = record.getSession(Buffer.from(preKeyProto.baseKey))
			if (!session) {
				throw new errors.SessionError('No session established for incoming PreKeyWhisperMessage')
			}

			const plaintext = await this.doDecryptWhisperMessage(Buffer.from(preKeyProto.message), session)
			await this.storeRecord(record)

			if (preKeyId) {
				await this.storage.removePreKey(preKeyId)
			}

			return plaintext
		})
	}

	async doDecryptWhisperMessage(messageBuffer: Uint8Array, session: SessionEntry): Promise<Buffer> {
		assertBuffer(messageBuffer)
		if (!session) {
			throw new TypeError('session required')
		}

		const versions = this._decodeTupleByte(messageBuffer[0]!)
		if (versions[1] > 3 || versions[0] < 3) {
			throw new Error('Incompatible version number on WhisperMessage')
		}

		const messageProto = messageBuffer.slice(1, -8)
		const message = protobufs.WhisperMessage.decode(messageProto)

		this.maybeStepRatchet(session, Buffer.from(message.ephemeralKey), message.previousCounter)

		const chain = session.getChain(Buffer.from(message.ephemeralKey))
		if (!chain) {
			throw new errors.SessionError('No chain found for message ephemeral key')
		}

		if (chain.chainType === ChainType.SENDING) {
			throw new Error('Tried to decrypt on a sending chain')
		}

		this.fillMessageKeys(chain, message.counter)

		if (!Object.prototype.hasOwnProperty.call(chain.messageKeys, message.counter)) {
			throw new errors.MessageCounterError('Key used already or never filled')
		}

		const messageKey = chain.messageKeys[message.counter]!
		delete chain.messageKeys[message.counter]

		const keys = crypto.deriveSecrets(messageKey, Buffer.alloc(32), Buffer.from('WhisperMessageKeys'))
		wipeBuffer(messageKey)
		const ourIdentityKey = await this.storage.getOurIdentity()

		const macInput = Buffer.alloc(messageProto.byteLength + 33 * 2 + 1)
		macInput.set(session.indexInfo.remoteIdentityKey)
		macInput.set(ourIdentityKey.pubKey, 33)
		macInput[33 * 2] = this._encodeTupleByte(VERSION, VERSION)
		macInput.set(messageProto, 33 * 2 + 1)

		crypto.verifyMAC(macInput, keys[1]!, messageBuffer.slice(-8), 8)

		const plaintext = crypto.decrypt(keys[0]!, Buffer.from(message.ciphertext), keys[2]!.slice(0, 16))
		delete session.pendingPreKey

		return plaintext
	}

	fillMessageKeys(chain: Chain, counter: number): void {
		while (chain.chainKey.counter < counter) {
			if (counter - chain.chainKey.counter > 2000) {
				throw new errors.SessionError('Over 2000 messages into the future!')
			}

			if (chain.chainKey.key === undefined) {
				throw new errors.SessionError('Chain closed')
			}

			const key = chain.chainKey.key
			chain.messageKeys[chain.chainKey.counter + 1] = crypto.calculateMAC(key, Buffer.from([1]))
			chain.chainKey.key = crypto.calculateMAC(key, Buffer.from([2]))
			chain.chainKey.counter += 1
		}
	}

	maybeStepRatchet(session: SessionEntry, remoteKey: Buffer, previousCounter: number): void {
		if (session.getChain(remoteKey)) {
			return
		}

		const ratchet = session.currentRatchet
		const previousRatchet = session.getChain(ratchet.lastRemoteEphemeralKey)
		if (previousRatchet) {
			this.fillMessageKeys(previousRatchet, previousCounter)
			wipeBuffer(previousRatchet.chainKey.key)
			delete previousRatchet.chainKey.key
		}

		this.calculateRatchet(session, remoteKey, false)

		const prevCounter = session.getChain(ratchet.ephemeralKeyPair.pubKey)
		if (prevCounter) {
			ratchet.previousCounter = prevCounter.chainKey.counter
			session.deleteChain(ratchet.ephemeralKeyPair.pubKey)
		}

		ratchet.ephemeralKeyPair = curve.generateKeyPair()
		this.calculateRatchet(session, remoteKey, true)
		ratchet.lastRemoteEphemeralKey = remoteKey
	}

	calculateRatchet(session: SessionEntry, remoteKey: Buffer, sending: boolean): void {
		const ratchet = session.currentRatchet
		const sharedSecret = curve.calculateAgreement(remoteKey, ratchet.ephemeralKeyPair.privKey)
		const masterKey = crypto.deriveSecrets(sharedSecret, ratchet.rootKey, Buffer.from('WhisperRatchet'), 2)
		const chainKey = sending ? ratchet.ephemeralKeyPair.pubKey : remoteKey

		session.addChain(chainKey, {
			messageKeys: {},
			chainKey: {
				counter: -1,
				key: masterKey[1]
			},
			chainType: sending ? ChainType.SENDING : ChainType.RECEIVING
		})

		ratchet.rootKey = masterKey[0]!
	}

	async hasOpenSession(): Promise<boolean> {
		return await this.queueJob(async () => {
			const record = await this.getRecord()
			if (!record) {
				return false
			}

			return record.haveOpenSession()
		})
	}

	async closeOpenSession(): Promise<void> {
		return await this.queueJob(async () => {
			const record = await this.getRecord()
			if (record) {
				const openSession = record.getOpenSession()
				if (openSession) {
					record.closeSession(openSession)
					await this.storeRecord(record)
				}
			}
		})
	}
				}
