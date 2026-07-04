import * as nodeCrypto from 'crypto'
import * as curve from './curve'
import type { KeyPair } from './curve'

function isNonNegativeInteger(n: number): boolean {
	return typeof n === 'number' && n % 1 === 0 && n >= 0
}

export interface SignedPreKey {
	keyId: number
	keyPair: KeyPair
	signature: Buffer
}

export interface PreKey {
	keyId: number
	keyPair: KeyPair
}

export const generateIdentityKeyPair = curve.generateKeyPair

export function generateRegistrationId(): number {
	const registrationId = nodeCrypto.randomBytes(2).readUInt16BE(0)
	return registrationId & 0x3fff
}

export function generateSignedPreKey(identityKeyPair: KeyPair, signedKeyId: number): SignedPreKey {
	if (
		!(identityKeyPair.privKey instanceof Buffer) ||
		identityKeyPair.privKey.byteLength !== 32 ||
		!(identityKeyPair.pubKey instanceof Buffer) ||
		identityKeyPair.pubKey.byteLength !== 33
	) {
		throw new TypeError('Invalid argument for identityKeyPair')
	}

	if (!isNonNegativeInteger(signedKeyId)) {
		throw new TypeError('Invalid argument for signedKeyId: ' + signedKeyId)
	}

	const keyPair = curve.generateKeyPair()
	const sig = curve.calculateSignature(identityKeyPair.privKey, keyPair.pubKey)

	return {
		keyId: signedKeyId,
		keyPair,
		signature: sig
	}
}

export function generatePreKey(keyId: number): PreKey {
	if (!isNonNegativeInteger(keyId)) {
		throw new TypeError('Invalid argument for keyId: ' + keyId)
	}

	const keyPair = curve.generateKeyPair()

	return {
		keyId,
		keyPair
	}
}
