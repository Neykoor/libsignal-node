import * as crypto from './crypto'

const VERSION = 0

async function iterateHash(data: ArrayBuffer, key: ArrayBuffer, count: number): Promise<ArrayBuffer> {
	const combined = new Uint8Array(Buffer.concat([Buffer.from(data), Buffer.from(key)])).buffer
	const result = crypto.hash(Buffer.from(combined))
	if (--count === 0) {
		return new Uint8Array(result).buffer
	}

	return iterateHash(new Uint8Array(result).buffer, key, count)
}

function shortToArrayBuffer(number: number): ArrayBuffer {
	return new Uint16Array([number]).buffer
}

function getEncodedChunk(hash: Uint8Array, offset: number): string {
	const chunk =
		(hash[offset]! * Math.pow(2, 32) +
			hash[offset + 1]! * Math.pow(2, 24) +
			hash[offset + 2]! * Math.pow(2, 16) +
			hash[offset + 3]! * Math.pow(2, 8) +
			hash[offset + 4]!) %
		100000

	let s = chunk.toString()
	while (s.length < 5) {
		s = '0' + s
	}

	return s
}

async function getDisplayStringFor(identifier: string, key: ArrayBuffer, iterations: number): Promise<string> {
	const bytes = Buffer.concat([Buffer.from(shortToArrayBuffer(VERSION)), Buffer.from(key), Buffer.from(identifier)])
	const arraybuf = new Uint8Array(bytes).buffer
	const output = new Uint8Array(await iterateHash(arraybuf, key, iterations))

	return (
		getEncodedChunk(output, 0) +
		getEncodedChunk(output, 5) +
		getEncodedChunk(output, 10) +
		getEncodedChunk(output, 15) +
		getEncodedChunk(output, 20) +
		getEncodedChunk(output, 25)
	)
}

export class FingerprintGenerator {
	private iterations: number

	constructor(iterations: number) {
		this.iterations = iterations
	}

	createFor(
		localIdentifier: string,
		localIdentityKey: ArrayBuffer,
		remoteIdentifier: string,
		remoteIdentityKey: ArrayBuffer
	): Promise<string> {
		if (
			typeof localIdentifier !== 'string' ||
			typeof remoteIdentifier !== 'string' ||
			!(localIdentityKey instanceof ArrayBuffer) ||
			!(remoteIdentityKey instanceof ArrayBuffer)
		) {
			throw new Error('Invalid arguments')
		}

		return Promise.all([
			getDisplayStringFor(localIdentifier, localIdentityKey, this.iterations),
			getDisplayStringFor(remoteIdentifier, remoteIdentityKey, this.iterations)
		]).then(fingerprints => fingerprints.sort().join(''))
	}
}
