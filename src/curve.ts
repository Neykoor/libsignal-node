import * as curveJs from 'curve25519-js'
import * as nodeCrypto from 'crypto'
import { getLogger } from './logger'

const PUBLIC_KEY_DER_PREFIX = Buffer.from([48, 42, 48, 5, 6, 3, 43, 101, 110, 3, 33, 0])
const PRIVATE_KEY_DER_PREFIX = Buffer.from([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32])
const KEY_BUNDLE_TYPE = Buffer.from([5])

export interface KeyPair {
	pubKey: Buffer
	privKey: Buffer
}

function prefixKeyInPublicKey(pubKey: Uint8Array): Buffer {
	return Buffer.concat([KEY_BUNDLE_TYPE, pubKey])
}

function validatePrivKey(privKey: Uint8Array): void {
	if (privKey === undefined) {
		throw new Error('Undefined private key')
	}

	if (!(privKey instanceof Uint8Array)) {
		throw new Error(`Invalid private key type: ${(privKey as unknown as object).constructor.name}`)
	}

	if (privKey.byteLength !== 32) {
		throw new Error(`Incorrect private key length: ${privKey.byteLength}`)
	}
}

function scrubPubKeyFormat(pubKey: Uint8Array): Buffer {
	if (!(pubKey instanceof Uint8Array)) {
		throw new Error(`Invalid public key type: ${(pubKey as unknown as object).constructor.name}`)
	}

	if (pubKey === undefined || ((pubKey.byteLength !== 33 || pubKey[0] !== 5) && pubKey.byteLength !== 32)) {
		throw new Error('Invalid public key')
	}

	if (pubKey.byteLength === 33) {
		return Buffer.from(pubKey.slice(1))
	}

	getLogger().warn('Expected pubkey of length 33, please report the ST and client that generated the pubkey')
	return Buffer.from(pubKey)
}

function unclampEd25519PrivateKey(clampedSk: Uint8Array): Uint8Array {
	const unclampedSk = new Uint8Array(clampedSk)

	unclampedSk[0] = unclampedSk[0]! | 6
	unclampedSk[31] = unclampedSk[31]! | 128
	unclampedSk[31] = unclampedSk[31]! & ~64

	return unclampedSk
}

export function getPublicFromPrivateKey(privKey: Uint8Array): Buffer {
	const unclampedPK = unclampEd25519PrivateKey(privKey)
	const keyPair = curveJs.generateKeyPair(unclampedPK)
	return prefixKeyInPublicKey(Buffer.from(keyPair.public))
}

export function generateKeyPair(): KeyPair {
	try {
		const { publicKey: publicDerBytes, privateKey: privateDerBytes } = nodeCrypto.generateKeyPairSync('x25519', {
			publicKeyEncoding: { format: 'der', type: 'spki' },
			privateKeyEncoding: { format: 'der', type: 'pkcs8' }
		})

		const pubKey = publicDerBytes.slice(PUBLIC_KEY_DER_PREFIX.length, PUBLIC_KEY_DER_PREFIX.length + 32)
		const privKey = privateDerBytes.slice(PRIVATE_KEY_DER_PREFIX.length, PRIVATE_KEY_DER_PREFIX.length + 32)

		return {
			pubKey: prefixKeyInPublicKey(pubKey),
			privKey
		}
	} catch {
		const keyPair = curveJs.generateKeyPair(nodeCrypto.randomBytes(32))
		return {
			privKey: Buffer.from(keyPair.private),
			pubKey: prefixKeyInPublicKey(Buffer.from(keyPair.public))
		}
	}
}

export function calculateAgreement(pubKeyInput: Uint8Array, privKey: Uint8Array): Buffer {
	const pubKey = scrubPubKeyFormat(pubKeyInput)
	validatePrivKey(privKey)

	if (!pubKey || pubKey.byteLength !== 32) {
		throw new Error('Invalid public key')
	}

	if (typeof nodeCrypto.diffieHellman === 'function') {
		const nodePrivateKey = nodeCrypto.createPrivateKey({
			key: Buffer.concat([PRIVATE_KEY_DER_PREFIX, privKey]),
			format: 'der',
			type: 'pkcs8'
		})
		const nodePublicKey = nodeCrypto.createPublicKey({
			key: Buffer.concat([PUBLIC_KEY_DER_PREFIX, pubKey]),
			format: 'der',
			type: 'spki'
		})

		return nodeCrypto.diffieHellman({
			privateKey: nodePrivateKey,
			publicKey: nodePublicKey
		})
	}

	const secret = curveJs.sharedKey(privKey, pubKey)
	return Buffer.from(secret)
}

export function calculateSignature(privKey: Uint8Array, message: Uint8Array): Buffer {
	validatePrivKey(privKey)

	if (!message) {
		throw new Error('Invalid message')
	}

	return Buffer.from(curveJs.sign(privKey, message))
}

export function verifySignature(pubKeyInput: Uint8Array, msg: Uint8Array, sig: Uint8Array): boolean {
	const pubKey = scrubPubKeyFormat(pubKeyInput)

	if (!pubKey || pubKey.byteLength !== 32) {
		throw new Error('Invalid public key')
	}

	if (!msg) {
		throw new Error('Invalid message')
	}

	if (!sig || sig.byteLength !== 64) {
		throw new Error('Invalid signature')
	}

	return curveJs.verify(pubKey, msg, sig)
}
