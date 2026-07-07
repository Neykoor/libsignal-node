import type { KeyPair } from './curve'
import type { SessionRecord } from './session-record'

export type { KeyPair }

export interface SignalStorage {
	loadSession(id: string): Promise<SessionRecord | undefined>
	storeSession(id: string, session: SessionRecord): Promise<void>
	isTrustedIdentity(identifier: string, identityKey: Buffer, direction?: number): Promise<boolean> | boolean
	saveIdentity?(identifier: string, identityKey: Buffer): Promise<boolean> | boolean
	removeIdentity?(identifier: string): Promise<void> | void
	loadPreKey(id?: number | string): Promise<KeyPair | undefined>
	removePreKey(id: number): Promise<void> | void
	loadSignedPreKey(id?: number | string): Promise<KeyPair | undefined> | KeyPair | undefined
	getOurRegistrationId(): Promise<number> | number
	getOurIdentity(): Promise<KeyPair> | KeyPair
}

export interface DeviceKeyBundle {
	registrationId: number
	identityKey: Buffer
	signedPreKey: {
		keyId: number
		publicKey: Buffer
		signature: Buffer
	}
	preKey?: {
		keyId: number
		publicKey: Buffer
	}
}

export interface IncomingPreKeyMessage {
	registrationId?: number
	identityKey: Buffer
	baseKey: Buffer
	preKeyId?: number
	signedPreKeyId?: number
	message: Buffer
}

export interface EncryptedMessage {
	type: number
	body: Buffer
	registrationId?: number
}
