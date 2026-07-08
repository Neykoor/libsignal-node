import * as nodeCrypto from 'crypto'

function assertBuffer(value: unknown): Uint8Array {
	if (!(value instanceof Uint8Array)) {
		throw TypeError(`Expected Uint8Array instead of: ${(value as unknown as object)?.constructor?.name}`)
	}

	return value
}

export function encrypt(key: Uint8Array, data: Uint8Array, iv: Uint8Array): Buffer {
	assertBuffer(key)
	assertBuffer(data)
	assertBuffer(iv)

	const cipher = nodeCrypto.createCipheriv('aes-256-cbc', key, iv)
	return Buffer.concat([cipher.update(data), cipher.final()])
}

export function decrypt(key: Uint8Array, data: Uint8Array, iv: Uint8Array): Buffer {
	assertBuffer(key)
	assertBuffer(data)
	assertBuffer(iv)

	const decipher = nodeCrypto.createDecipheriv('aes-256-cbc', key, iv)
	return Buffer.concat([decipher.update(data), decipher.final()])
}

export function calculateMAC(key: Uint8Array, data: Uint8Array): Buffer {
	assertBuffer(key)
	assertBuffer(data)

	const hmac = nodeCrypto.createHmac('sha256', key)
	hmac.update(data)
	return Buffer.from(hmac.digest())
}

export function hash(data: Uint8Array): Buffer {
	assertBuffer(data)

	const sha512 = nodeCrypto.createHash('sha512')
	sha512.update(data)
	return sha512.digest()
}

export function deriveSecrets(input: Uint8Array, salt: Uint8Array, info: Uint8Array, chunks?: number): Buffer[] {
	assertBuffer(input)
	assertBuffer(salt)
	assertBuffer(info)

	if (salt.byteLength !== 32) {
		throw new Error('Got salt of incorrect length')
	}

	const count = chunks || 3
	if (count < 1 || count > 3) {
		throw new Error('chunks must be between 1 and 3')
	}

	const PRK = calculateMAC(salt, input)
	const infoArray = new Uint8Array(info.byteLength + 1 + 32)
	infoArray.set(info, 32)
	infoArray[infoArray.length - 1] = 1

	const signed = [calculateMAC(PRK, Buffer.from(infoArray.slice(32)))]

	if (count > 1) {
		infoArray.set(signed[signed.length - 1]!)
		infoArray[infoArray.length - 1] = 2
		signed.push(calculateMAC(PRK, Buffer.from(infoArray)))
	}

	if (count > 2) {
		infoArray.set(signed[signed.length - 1]!)
		infoArray[infoArray.length - 1] = 3
		signed.push(calculateMAC(PRK, Buffer.from(infoArray)))
	}

	return signed
}

export function verifyMAC(data: Uint8Array, key: Uint8Array, mac: Uint8Array, length: number): void {
	const calculatedMac = calculateMAC(key, data).slice(0, length)

	if (mac.length !== length || calculatedMac.length !== length) {
		throw new Error('Bad MAC length')
	}

	if (!nodeCrypto.timingSafeEqual(mac, calculatedMac)) {
		throw new Error('Bad MAC')
	}
}
